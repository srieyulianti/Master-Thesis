#include "tensorflow/lite/c/c_api.h"
#include "tensorflow/lite/c/c_api_experimental.h"
#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/c/builtin_op_data.h"
#include "tensorflow/lite/c/ujpeg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Dispose of the model and interpreter objects.
int disposeTfLiteObjects(TfLiteModel* m_Model, TfLiteInterpreter* m_Interpreter)
{
    if(m_Model != NULL)
    {
      TfLiteModelDelete(m_Model);
    }

    if(m_Interpreter)
    {
      TfLiteInterpreterDelete(m_Interpreter);
    }
}

// The main function.
int ObjectDetector(char* model_name, char* image_file) 
{
    TfLiteStatus tflStatus;

    // Create JPEG image object.
    ujImage img = ujCreate();

    // Decode the JPEG file.
    ujDecodeFile(img, image_file);

    // Check if decoding was successful.
    if(ujIsValid(img) == 0){
        return 1;
    }
    
    // There will always be 3 channels.
    int channel = 3;

    // Height will always be 224, no need for resizing.
    int height = ujGetHeight(img);

    // Width will always be 224, no need for resizing.
    int width = ujGetWidth(img);

    // The image size is channel * height * width.
    int imageSize = ujGetImageSize(img);

    // Fetch RGB data from the decoded JPEG image input file.
    uint8_t* p_Image = (uint8_t*)ujGetImage(img, NULL);

    // The array that will collect the JPEG RGB values.
    float imageDataBuffer[imageSize];

    // RGB range is 0-255. Scale it to 0-1.
    int j=0;
    for(int i = 0; i < imageSize; i++){
        imageDataBuffer[i] = (float)p_Image[i] / 255.0;
    }

    // Load model.
    TfLiteModel* model = TfLiteModelCreateFromFile(model_name);

    // Create the interpreter.
    TfLiteInterpreter* interpreter = TfLiteInterpreterCreate(model, NULL);

    // Allocate tensors.
    tflStatus = TfLiteInterpreterAllocateTensors(interpreter);

    // Log and exit in case of error.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error allocating tensors.
");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }
    
    int inputDims[4] = {1, 224, 224, 3};
    tflStatus = TfLiteInterpreterResizeInputTensor(interpreter, 0, inputDims, 4);

    // Log and exit in case of error.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error resizing tensor.
");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }

    tflStatus = TfLiteInterpreterAllocateTensors(interpreter);

    // Log and exit in case of error.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error allocating tensors after resize.
");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }

    // The input tensor.
    TfLiteTensor* inputTensor = TfLiteInterpreterGetInputTensor(interpreter, 0);

    // Copy the JPEG image data into into the input tensor.
    tflStatus = TfLiteTensorCopyFromBuffer(inputTensor, imageDataBuffer, imageSize);
    
    // Log and exit in case of error.
    // FIXME: Error occurs here.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error copying input from buffer.
");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }

    // Invoke interpreter.
    tflStatus = TfLiteInterpreterInvoke(interpreter);

    // Log and exit in case of error.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error invoking interpreter.
");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }

    // Extract the output tensor data.
    const TfLiteTensor* outputTensor = TfLiteInterpreterGetOutputTensor(interpreter, 0);

    // There are three possible labels. Size the output accordingly.
    float output[3];

    tflStatus = TfLiteTensorCopyToBuffer(outputTensor, output, 3 * sizeof(float));

    // Log and exit in case of error.
    if(tflStatus != kTfLiteOk)
    {
      printf("Error copying output to buffer.");
      disposeTfLiteObjects(model, interpreter);
      return 1;
    }

    // Print out classification result.
    printf("Confidences: %f, %f, %f.", output[0], output[1], output[2]); 

    // Dispose of the TensorFlow objects.
    disposeTfLiteObjects(model, interpreter);
    
    // Dispoice of the image object.
    ujFree(img);
    
    return 0;
}
