import os
import math
import json
from hashlib import md5
from collections import Counter
import xml.etree.ElementTree as Et

import ssdeep
from sklearn.metrics.pairwise import cosine_similarity

"""
2020.07.23 HideOnHouse
Package of frequently used method to get information of docx files

2020.07.30 HideOnHouse
Update some methods

2020.07.31 HideOnHouse
Performance boost
"""


def read_bytes(file_path):
    """

    :param file_path: target file
    :return: file data
    """
    with open(file_path, 'rb') as target_file:
        return target_file.read()


def parse_xml(xml_path):
    """

    :param xml_path: xml file path to parse
    :return: tuple composed of two tuple that contains xml file's all tag and all text
    """
    result = [[], []]
    tree = Et.parse(xml_path)
    for node in tree.iter():
        tag = node.tag
        if node.tag.count('}') != 0:
            tag = node.tag.split('}')[-1]
        text = node.text
        result[0].append(tag)
        result[1].append(text)
    result = tuple(result)
    return result


def check_xml(xml_path, target_tag=(), target_text=()):
    """

    :param xml_path: xml file path to check
    :param target_tag: desired tag to check
    :param target_text: desired text to check
    :return: return true if target tag or text exist in xml file else false
    """
    temp = parse_xml(xml_path)
    for tag in target_tag:
        if tag in temp[0]:
            return True

    for text in target_text:
        if text in temp[1]:
            return True


def file_md5(file_path):
    hash_md5 = md5()
    with open(file_path, "rb") as target_file:
        for chunk in iter(lambda: target_file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def store_vt_report(file_path, public_api):
    # noinspection SpellCheckingInspection
    """
        Don't use this function over 50000 times per day
        :param file_path: path of desired file to upload to VirusTotal
        :param public_api: your public api
        :return: None, create json file named file_path.json
    """
    public_api = VirusTotalVersion3.PublicAPI(public_api)
    public_api.post_files_scan(file_path)
    report = public_api.get_file_info(file_md5(file_path))
    with open(file_path + os.extsep + '.json', 'w') as target_file:
        json.dump(report, target_file)


def get_entropy(raw):
    """

    :param raw: class typing.IO
    :return: entropy of file
    """
    e = 0
    counter = Counter(raw)
    for count in counter.values():
        p_x = count / len(raw)
        e += - p_x * math.log2(p_x)
    return e


def get_folder_entropy(folder_path, target):
    """

    :param folder_path:
    :param target: target extension
    :return: entropy of all file in folder_path
    """
    result = []
    for path, dirs, files in os.walk(folder_path):
        for file in files:
            ext = file.split(os.extsep)[-1]
            if target.count(ext) != 0:
                raw = read_bytes(path + os.sep + file)
                result.append((path + os.sep + file, get_entropy(raw)))
    result = tuple(result)
    return result


def check_pe_injected(file_path):
    """

    :param file_path: target file to check
    :return: true if file seems contain PE
    """
    raw = read_bytes(file_path)

    mz_idx_list = get_mz_indexes(raw)

    is_inject = False
    for idx in mz_idx_list:
        offset = int.from_bytes(raw[idx + 60:idx + 64], byteorder='little')
        if raw[idx + offset:idx + offset + 2] == b"PE":
            is_inject = True
    return is_inject


def get_mz_indexes(raw):
    """

    :param raw: raw data of file
    :return: list of file indexes 'mz' occur
    """
    mz_idx_list = []
    init_idx = -1
    flag = False
    while True:
        try:
            if not flag:
                init_idx = raw.index(b"MZ")
                mz_idx_list.append(init_idx)
                flag = True

            start = init_idx + 3
            new_idx = start + raw[start:].index(b"MZ")
            mz_idx_list.append(new_idx)
            init_idx = new_idx

        except ValueError:
            return mz_idx_list


def get_structure(folder_path, xml=False):
    """

    :param folder_path: target unzipped docx folder
    :param xml: also make structure of xml file if true
    :return: sorted tuple of unzipped docx structure
    """
    parsed = []
    for path, dirs, files in os.walk(folder_path):
        for file in files:
            if file.split(os.extsep)[-1] == 'xml' and xml:
                parsed.append(make_tag_tree(path + os.sep + file))
            else:
                parsed.append(path + os.sep + file)
    parsed = tuple(sorted(parsed))
    return parsed


def __get_child(parsed_list, etree_root, tag_stack):
    if list(etree_root) is None:
        return parsed_list
    else:
        root_tag = etree_root.tag
        root_tag = root_tag[root_tag.find("}") + 1:]
        for child in etree_root:
            tag_stack.append(root_tag)
            child_tag = child.tag
            child_tag = child_tag[child_tag.find('}') + 1:]
            parsed_list.append('\\'.join(tag_stack) + '\\' + child_tag)
            __get_child(parsed_list, child, tag_stack)
            tag_stack.pop()


def make_tag_tree(xml_path):
    """

    :param xml_path: target xml file path
    :return: structural list of xml file tag
    """
    parsed_list = []
    root_stack = []
    xml_obj = Et.parse(xml_path)
    xml_root = xml_obj.getroot()
    __get_child(parsed_list, xml_root, root_stack)
    parsed_list = list(set(parsed_list))
    parsed_list.sort()
    return parsed_list


# noinspection DuplicatedCode
def get_vt_tag(file_name):
    """

    :param file_name: Desired file name to find tag
    :return: VirusTotal tag, separated by period
    """
    f = "None"
    try:
        f = open(file_name, 'r')
    except FileNotFoundError:
        for path, dirs, files in os.walk(os.curdir):
            for file in files:
                if file.split(os.sep)[0] == file_name and file.split(os.extsep)[-1] == 'json':
                    f = open(path + os.sep + file, 'r')
    temp = json.load(f)
    try:
        vt_tag = '.'.join(temp['data']['attributes']['tags'])
    except KeyError:
        vt_tag = 'None'
    f.close()
    if vt_tag is None:
        vt_tag = 'None'
    return vt_tag


# noinspection DuplicatedCode
def get_vt_detection(file_name, av_name='Symantec'):
    """

    :param file_name: Desired file name to find tag
    :param av_name: Desired VirusTotal detection AV(Anti Virus) engine
    :return: desired AV's detection label
    """
    f = 'None'
    try:
        f = open(file_name, 'r')
    except FileNotFoundError:
        for path, dirs, files in os.walk(os.curdir):
            for file in files:
                if file.split(os.sep)[0] == file_name and file.split(os.extsep)[-1] == 'json':
                    f = open(path + os.sep + file, 'r')
    temp = json.load(f)
    try:
        vt_detection = temp['data']['attributes']['last_analysis_results'][av_name]['result']
    except KeyError:
        vt_detection = 'None'
    f.close()
    if vt_detection is None:
        vt_detection = 'None'
    return vt_detection


def get_ssdeep(file_path):
    """

    :param file_path: absolute path of desired file
    :return: ssdeep
    """
    return ssdeep.hash_from_file(file_path)


def compare_ssdeep(ssdeep1, ssdeep2):
    """

    :return: ssdeep score between two ssdeep
    """
    return ssdeep.compare(ssdeep1, ssdeep2)


def get_jaccard(set1, set2):
    """

    :return: jaccard similarity between two set, length of set1, set2, intersection
    """
    return (len(set1.intersection(set2)) / len(set1.union(set2))), len(set1), len(set2), set1.intersection(set2)


def get_cosine(vector1, vector2):
    """

    :return: cosine similarity between two vector
    """
    return cosine_similarity(vector1, vector2)[0][0]


def get_ae_chunk(file_path, window_size):
    """

    :param file_path: absolute path of desired file
    :param window_size: Asymmetric Extremum chunking window size
    :return: list that contain hex value of each chunk
    """
    answer = list()
    result = []
    with open(file_path, 'rb') as f:
        stream = f.read()
        temp = -1
        max_point = stream[0]
        chunked = [0]
        for idx in range(len(stream) - 1):
            temp += 1
            if stream[idx] > max_point:
                max_point = stream[idx]
                temp = 0
            elif temp == window_size:
                chunked.append(idx)
                answer.append(chunked)
                temp = -1
                chunked = [idx + 1]
                max_point = stream[idx + 1]
        chunked.append(idx + 1)
        answer.append(chunked)
        for idx in answer:
            result.append(stream[idx[0]:idx[1]])
    return result


def convert_name_to_path(file_name, extension):
    """
    Convert file name to absolute file path within current directory
    :param file_name: Desired file name to convert
    :param extension: extension of desired file
    :return: absolute file path
    """
    for path, dirs, files in os.walk(os.curdir):
        for file in files:
            if file.split(os.extsep)[0] == file_name and file.split(os.extsep)[-1] == extension:
                return path + os.sep + file
