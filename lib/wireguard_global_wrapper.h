#pragma once

#include <node_api.h>
#include <iostream>
#include <cstring>
#include "utils.h"

napi_value SetLoggingFunction(napi_env env, napi_callback_info info);

napi_value GenerateSecretKey(napi_env env, napi_callback_info info);

napi_value GenerateSecretKeyBase64(napi_env env, napi_callback_info info);

napi_value GetPublicKeyFrom(napi_env env, napi_callback_info info);

napi_value CheckBase64EncodedX25519Key(napi_env env, napi_callback_info info);

napi_status RegisterGlobalFunctions(napi_env env, napi_value exports);

napi_status RegisterGlobalConstants(napi_env env, napi_value exports);
