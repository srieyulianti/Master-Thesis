#include "tensorflow/lite/c/c_api.h"
#include "tensorflow/lite/c/c_api_experimental.h"
#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/c/builtin_op_data.h"
#include "tensorflow/lite/c/ujpeg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int disposeTfLiteObjects(TfLiteModel* m_Model, TfLiteInterpreter* m_Interpreter);
int ObjectDetector(char* model_name, char* image_file);