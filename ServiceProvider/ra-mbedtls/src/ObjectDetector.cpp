#include "ObjectDetector.h"
#include <opencv2/imgproc.hpp>
/*#include "tensorflow/lite/c/c_api.h"*/


using namespace cv;

ObjectDetector::ObjectDetector(const char *tfliteModel, long modelSize, bool quantized) {
	m_modelQuantized = quantized;
	if (modelSize > 0) {
		initDetectionModel(tfliteModel, modelSize);
	}
}

ObjectDetector::~ObjectDetector() {
	if (m_modelBytes != nullptr) {
		free(m_modelBytes);
		m_modelBytes = nullptr;
	}

	m_hasDetectionModel = false;
}

// Credit: https://github.com/YijinLiu/tf-cpu/blob/master/benchmark/obj_detect_lite.cc
void ObjectDetector::initDetectionModel(const char *tfliteModel, long modelSize) {
	if (modelSize < 1) { return; }

	// Copy to model bytes as the caller might release this memory while we need it (EXC_BAD_ACCESS error on ios)
	m_modelBytes = (char *) malloc(sizeof(char) * modelSize);
	memcpy(m_modelBytes, tfliteModel, sizeof(char) * modelSize);
	m_model = TfLiteModelCreate(m_modelBytes, modelSize);

	if (m_model == nullptr) {
		printf("Failed to load model");
		return;
	}

	// Build the interpreter
    TfLiteInterpreterOptions* options = TfLiteInterpreterOptionsCreate();
    TfLiteInterpreterOptionsSetNumThreads(options, 1);

    // Create the interpreter.
    m_interpreter = TfLiteInterpreterCreate(m_model, options);
	if (m_interpreter == nullptr) {
		printf("Failed to create interpreter");
		return;
	}

	// Allocate tensor buffers.
	if (TfLiteInterpreterAllocateTensors(m_interpreter) != kTfLiteOk) {
		printf("Failed to allocate tensors!");
		return;
	}

	// Find input tensors.
	if (TfLiteInterpreterGetInputTensorCount(m_interpreter) != 1) {
		printf("Detection model graph needs to have 1 and only 1 input!");
		return;
	}

	m_input_tensor = TfLiteInterpreterGetInputTensor(m_interpreter, 0);
	if (m_modelQuantized && TfLiteTensorType(m_input_tensor) != kTfLiteUInt8) {
		printf("Detection model input should be kTfLiteUInt8!");
		return;
	}

	if (!m_modelQuantized && TfLiteTensorType(m_input_tensor) != kTfLiteFloat32) {
		printf("Detection model input should be kTfLiteFloat32!");
		return;
	}

	if (TfLiteTensorDim(m_input_tensor, 0) != 1 ||
		TfLiteTensorDim(m_input_tensor, 1) != DETECTION_MODEL_SIZE ||
		TfLiteTensorDim(m_input_tensor, 2) != DETECTION_MODEL_SIZE ||
		TfLiteTensorDim(m_input_tensor, 3) != DETECTION_MODEL_CNLS) {
		printf("Detection model must have input dims of 1x%ix%ix%i", DETECTION_MODEL_SIZE,
			   DETECTION_MODEL_SIZE, DETECTION_MODEL_CNLS);
		return;
	}

	// Find output tensors.
	if (TfLiteInterpreterGetOutputTensorCount(m_interpreter) != 4) {
		printf("Detection model graph needs to have 4 and only 4 outputs!");
		return;
	}

	m_output_locations = TfLiteInterpreterGetOutputTensor(m_interpreter, 0);
	m_output_classes = TfLiteInterpreterGetOutputTensor(m_interpreter, 1);
	m_output_scores = TfLiteInterpreterGetOutputTensor(m_interpreter, 2);
	m_num_detections = TfLiteInterpreterGetOutputTensor(m_interpreter, 3);

	m_hasDetectionModel = true;
}

DetectResult* ObjectDetector::detect(Mat src) {
	DetectResult* res = new DetectResult[DETECT_NUM];
	if (!m_hasDetectionModel) {
		return res;
	}

	Mat image;
	resize(src, image, Size(DETECTION_MODEL_SIZE, DETECTION_MODEL_SIZE), 0, 0, INTER_AREA);
	int cnls = image.type();
	if (cnls == CV_8UC1) {
		cvtColor(image, image, COLOR_GRAY2RGB);
	} else if (cnls == CV_8UC3) {
		cvtColor(image, image, COLOR_BGR2RGB);
	} else if (cnls == CV_8UC4) {
		cvtColor(image, image, COLOR_BGRA2RGB);
	}

	void* TensorData = TfLiteTensorData(m_input_tensor);
	if (m_modelQuantized) {
		// Copy image into input tensor
		//void* TensorData = TfLiteTensorData(m_input_tensor);
		uchar *dst = (uchar*)TensorData;

		memcpy(dst, image.data,
			   sizeof(uchar) * DETECTION_MODEL_SIZE * DETECTION_MODEL_SIZE * DETECTION_MODEL_CNLS);
	} else {
		// Normalize the image based on std and mean (p' = (p-mean)/std)
		Mat fimage;
		image.convertTo(fimage, CV_32FC3, 1 / IMAGE_STD, -IMAGE_MEAN / IMAGE_STD);

		// Copy image into input tensor
		float *dst = (float*)TensorData;
		memcpy(dst, fimage.data,
			   sizeof(float) * DETECTION_MODEL_SIZE * DETECTION_MODEL_SIZE * DETECTION_MODEL_CNLS);
	}

	if (TfLiteInterpreterInvoke(m_interpreter) != kTfLiteOk) {
		printf("Error invoking detection model");
		return res;
	}
	void* OutputLocation = TfLiteTensorData(m_output_locations);
	void* OutputClasses = TfLiteTensorData(m_output_classes);
	void* OutputScores = TfLiteTensorData(m_output_scores);
	void* OutputNumDetections = TfLiteTensorData(m_num_detections);

	const float *detection_locations = (float*)OutputLocation;
	const float *detection_classes = (float*)OutputClasses;
	const float *detection_scores = (float*)OutputScores;
	const int num_detections = (int) *(float*)OutputNumDetections;

	for (int i = 0; i < num_detections && i < DETECT_NUM; ++i) {
		res[i].score = detection_scores[i];
		res[i].label = (int) detection_classes[i];

		// Get the bbox, make sure its not out of the image bounds, and scale up to src image size
		res[i].ymin = std::fmax(0.0f, detection_locations[4 * i] * src.rows);
		res[i].xmin = std::fmax(0.0f, detection_locations[4 * i + 1] * src.cols);
		res[i].ymax = std::fmin(float(src.rows - 1), detection_locations[4 * i + 2] * src.rows);
		res[i].xmax = std::fmin(float(src.cols - 1), detection_locations[4 * i + 3] * src.cols);
	}

	return res;
}
