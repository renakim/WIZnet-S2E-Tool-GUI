import re


def compare_version(version1, version2):
    """ 
    Version compare: x.x.x 
    return value:
        value < 0: version1 < version2
        value = 0: version1 < version2
        value > 0: version1 > version2
    """
    def normalize(v):
        # return [x for x in re.sub(r'(\.0+)*$','',v).split('.')]
        return [x for x in re.sub(r"(\.0+\.[dev])*$", "", v).split(".")]

    obj1 = normalize(version1)
    obj2 = normalize(version2)
    return (obj1 > obj2) - (obj1 < obj2)
    # if return value < 0: version2 upper than version1


if __name__ == "__main__":
    print(compare_version('1.3.2', '1.2.2'))
