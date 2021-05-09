#ifndef OBJECT_DETECTOR_H_
#define OBJECT_DETECTOR_H_

#include "tensorflow/lite/c/c_api.h"
#include "tensorflow/lite/c/c_api_experimental.h"
#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/c/builtin_op_data.h"
#include "ujpeg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int disposeTfLiteObjects(TfLiteModel* m_Model, TfLiteInterpreter* m_Interpreter);
int ObjectDetector(char* model_name, char* image_file, char buffer[1024]);

#endif //OBJECT_DETECTOR_H_ 
