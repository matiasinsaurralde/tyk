import importlib, sys

class MiddlewareLoader():
    def __init__(self, mw=None):
        self.mw = mw

    def find_module(self, module_name, package_path):
      return self

    def load_module(self, fullname):
      base_path = "{0}_{1}".format(self.mw.api_id, self.mw.middleware_id)
      module_name = "{0}.{1}".format(base_path, fullname)
      module_path = "middleware/bundles/{0}/{1}.py".format(base_path, fullname)

      spec = importlib.util.spec_from_file_location(fullname, module_path)
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)

      sys.modules[fullname] = module
      # setattr(self.mw.module, fullname, module)
      self.mw.imported_modules.append(fullname)

      return module