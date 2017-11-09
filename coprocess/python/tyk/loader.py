import importlib, sys, os
from gateway import TykGateway as tyk

class MiddlewareLoader():
    def __init__(self, mw=None):
        self.mw = mw

    def find_module(self, module_name, package_path):
      self.base_path = "{0}_{1}".format(self.mw.api_id, self.mw.middleware_id)
      self.module_path = "middleware/bundles/{0}/{1}.py".format(self.base_path, module_name)
      if not os.path.exists(self.module_path):
        error_msg = "Your bundle doesn't contain '{0}'".format(module_name)
        tyk.log(error_msg, "error")
        return None
      return self

    def load_module(self, module_name):
      spec = importlib.util.spec_from_file_location(module_name, self.module_path)
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)

      sys.modules[module_name] = module
      self.mw.imported_modules.append(module_name)

      return module