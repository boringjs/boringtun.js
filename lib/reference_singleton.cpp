#include "reference_singleton.h"
#include <node_api.h>

ReferenceSingleton *ReferenceSingleton::instance_ = nullptr;

ReferenceSingleton *ReferenceSingleton::GetInstance() {
  if (instance_ == nullptr) {
    instance_ = new ReferenceSingleton();
  }
  return instance_;
}

napi_ref ReferenceSingleton::SetReference(const std::string &key, napi_env env, napi_value value) {
  napi_status status = napi_ok;

  if (ref_map_.count(key) > 0) {
    auto [ref_prev, env_prev] = ref_map_.at(key);
    status = napi_delete_reference(env_prev, ref_prev);
    ref_map_.erase(key);
  }

  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Problem with deleting napi ref");
    return nullptr;
  }

  napi_ref ref = nullptr;
  status = napi_create_reference(env, value, 1, &ref);
  if (status != napi_ok) {
    napi_throw_error(env, nullptr, "Cannot create reference for napi object");
    return nullptr;
  }

  ref_map_[key] = {ref, env};

  return ref;
}

ReferenceSingleton::napi_ref_env ReferenceSingleton::GetRefEnv(const std::string &key) {
  return ref_map_.at(key);
}

bool ReferenceSingleton::IsRefExists(const std::string &key) {
  return ref_map_.count(key) > 0;
}
