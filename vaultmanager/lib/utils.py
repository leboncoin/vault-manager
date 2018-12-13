#
# Utils methods
#


def list_to_string(logger, lst, delimiter="", separator=","):
    """
    Convert a list to string

    :param logger: logger instance
    :type logger: logger
    :param lst: list to serialize
    :type lst: list
    :param delimiter: quoting string
    :type delimiter: str
    :param separator: separator between list elements
    :type separator: str

    :return: str
    """
    logger.debug("Converting list " + str(lst))
    lst = [elem for elem in lst if lst]
    target = ""
    for idx, elem in enumerate(lst):
        if idx != 0:
            target += separator
        target += delimiter + elem + delimiter
    logger.debug("Returning: " + target)
    return target


def keys_exists_in_dict(logger, dictionary, keys):
    """
    Check if all keys in keys are present in dict_to_inspect and if the
    key value is in included_values and not in excluded_values

    :param logger: logger instance
    :type logger: logger
    :param dictionary: Will look for keys in this dictionary
    :type dictionary: dict
    :param keys: List of keys to look for with wanted/unwanted values
    :type keys: list(dict)

    :return: list of missing keys
    """
    logger.debug("Inspecting dictionary for keys %s" % keys)
    logger.debug("Normalizing dictionary values")
    for key in keys:
        if "key" not in key:
            raise ValueError("Dictionary not in a valid format")
        if "inc" not in key:
            key['inc'] = []
        if "exc" not in key:
            key['exc'] = []
    missing_keys = []
    for key in keys:
        if key['key'] not in dictionary or dictionary[key['key']] in key['exc']:
            logger.debug("Key %s not found or value in excluded values" % key)
            missing_keys.append(key)
        if not len(key['inc']) or dictionary[key['key']] in key['inc']:
            logger.debug("Key %s found and value in included values" % key)
    return missing_keys
