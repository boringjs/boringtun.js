#pragma once

#include <map>
#include <utility>
#include <node_api.h>

class ReferenceSingleton {
public:
  using napi_ref_env = std::pair<napi_ref, napi_env>;
  static ReferenceSingleton *GetInstance();

  napi_ref SetReference(const std::string &key, napi_env env, napi_value value);

  napi_ref_env GetRefEnv(const std::string &key);

  bool IsRefExists(const std::string &key);
private:
  static ReferenceSingleton *instance_;

  ReferenceSingleton() {}

  std::map<std::string, napi_ref_env> ref_map_;
};