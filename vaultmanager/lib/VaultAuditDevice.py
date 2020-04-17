import hashlib


class VaultAuditDevice:
    type = None
    path = None
    description = None
    options = None

    def __init__(self, type, path, description, options):
        self.type = type
        self.path = path.replace("/", "")
        self.description = (description if description else "")
        self.options = options

    def get_device_unique_id(self):
        unique_str = str(self.type + self.path +
                         self.description + str(self.options))
        sha256_hash = hashlib.sha256(unique_str.encode()).hexdigest()
        return sha256_hash

    def __eq__(self, other):
        return self.get_device_unique_id() == other.get_device_unique_id()

    def __repr__(self):
        return ("Path: %s - Type: %s - Desc: %s - Options: %s - Hash : %s" %
                (self.path, self.type, self.description, str(self.options),
                 self.get_device_unique_id()))
