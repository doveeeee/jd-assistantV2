# coding: utf-8
import json
import time
import uuid
import hashlib
import base64
import requests
import random
import cv2
import numpy as np
from Crypto.Cipher import AES
from urllib.parse import quote

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
             "Chrome/89.0.4389.90 Safari/537.36"

sess = requests.session()
fp = "6a3b8f6dca51ef0ed4bc2da8d9cfdddf"


def rshift(val, n):
    return (val % 0x100000000) >> n


def td_encrypt(data):
    secret = "23IL<N01c7KvwZO56RSTAfghiFyzWJqVabGH4PQdopUrsCuX*xeBjkltDEmn89.-"
    js = json.dumps(data, separators=(',', ':'))
    res = quote(js, safe='', encoding=None, errors=None)

    q, z, t, l = "", "", 0, 0

    # r = (q = u.charCodeAt(l++)) >> 2
    q = ord(res[l])
    l += 1
    r = q >> 2

    # d = (3 & q) << 4 | (q = u.charCodeAt(l++)) >> 4;
    tmp = (3 & q) << 4
    q = ord(res[l])
    l += 1
    d = tmp | q >> 4

    # h = (15 & q) << 2 | (t = u.charCodeAt(l++)) >> 6;
    tmp = (15 & q) << 2
    t = ord(res[l])
    l += 1
    h = tmp | t >> 6

    g = 63 & t

    # isNaN(q) ? h = g = 64 : isNaN(t) && (g = 64);
    if not isinstance(q, int):
        h = g = 64
    elif not isinstance(t, int):
        g = 64

    z = z + secret[r] + secret[d] + secret[h] + secret[g]

    while l < len(res):
        # r = (q = u.charCodeAt(l++)) >> 2
        q = ord(res[l])
        l += 1
        r = q >> 2

        # d = (3 & q) << 4 | (q = u.charCodeAt(l++)) >> 4;
        tmp = (3 & q) << 4
        try:
            q = ord(res[l])
        except IndexError:
            q = 'NaN'
        l += 1
        d = tmp | q >> 4

        # h = (15 & q) << 2 | (t = u.charCodeAt(l++)) >> 6;
        tmp = (15 & q) << 2
        try:
            t = ord(res[l])
        except IndexError:
            t = 'NaN'
        l += 1
        h = tmp | ((t >> 6) if isinstance(t, int) else 0)

        g = 63 & t if isinstance(t, int) else 0

        # isNaN(q) ? h = g = 64 : isNaN(t) && (g = 64);
        if q == 'NaN':
            h = g = 64
        elif t == 'NaN':
            g = 64
        try:
            z = z + secret[r] + secret[d] + secret[h] + secret[g]
        except IndexError:
            z = z + secret[r] + secret[d] + secret[h]
    return z + "/"


def aes_encrypt(data):
    BLOCK_SIZE = 16  # Bytes

    def pad(s):
        return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

    data = pad(data)
    key = bytes.fromhex("4c5751554935255042304e6458323365")
    iv = bytes.fromhex("30313233343536373839616263646566")
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b32encode(aes.encrypt(data.encode())).decode('utf8').rstrip("=")


def gen_jd_shadow():
    res = "passport.jd.com/new/login.aspx" + str(uuid.uuid4()) + str(get_timestamp())
    res = "JD1" + gen_sha1(res)
    res += str(gen_jdd_mac(res))
    return aes_encrypt(res)


def gen_jdd_mac(w):
    key = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 " \
          "79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 " \
          "F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A " \
          "8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 " \
          "3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 " \
          "45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 " \
          "CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB " \
          "B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 " \
          "7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 " \
          "1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 " \
          "8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 " \
          "D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 " \
          "44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 " \
          "206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 " \
          "B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 " \
          "73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 " \
          "F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 " \
          "89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E " \
          "38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 " \
          "41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 " \
          "CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 " \
          "B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F " \
          "72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 " \
          "0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 " \
          "88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 " \
          "D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC " \
          "40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 " \
          "24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 " \
          "B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D".split(" ")
    p = list(map(lambda x: int(x, 16), key))
    y = -1
    for i in w:
        y = rshift(y, 8) ^ p[255 & (y ^ ord(i))]
    return rshift(-1 ^ y, 0)


def gen_sha1(string, encoding='utf8'):
    sha1 = hashlib.sha1()
    sha1.update(string.encode(encoding))
    return sha1.hexdigest().upper()


def get_timestamp():
    return int(time.time() * 1000)


def get_jd_risk_token_id():
    url = f"https://gia.jd.com/y.html?v={random.random()}&o=passport.jd.com/new/login.aspx"
    headers = {
        "User-Agent": user_agent,
        "Host": "gia.jd.com",
        "Referer": "https://passport.jd.com/",
    }
    resp = sess.get(url, headers=headers)
    return resp.text[resp.text.find('\'') + 1:resp.text.rfind('\'')]


def gen_eid_data():
    def gen_g():
        x = {
            "addBehavior": False,
            "asr": "44100",
            "browser": "applewebkit_chrome",
            "browserVersion": "537.36",
            "canvas": "76021f96b4713622ddfb888ec643df8a",
            "ccn": 8,
            "colorDepth": 24,
            "cpu": "NA",
            "indexedDb": True,
            "language": "zh-CN",
            "localStorage": True,
            "openDatabase": True,
            "origin": "pc",
            "os": "windows",
            "osVersion": "NT",
            "platform": "Win32",
            "plugins": "8842e269feab82a16a81be6fb1301e38",
            "screenResolution": "1440x2560",
            "sessionStorage": True,
            "timezoneOffset": -8,
            "track": "NA",
            "userAgent": "72766ab2b1c85af98adbbb9683600fdf",
            "webgl": "ec9a5e935437d1452ff0c0ce92d56e9b",
        }
        return td_encrypt(x)

    return gen_g()


def gen_eid_param():
    param = {
        "f": "1",
        # "fc": "5UZ3GH3L45HEOVWXIIH7WBFUM446YT4HJ3EWG7JF2KGLGVIRCZDOPFCGP3AAZJPFLREWT5HAO5FUHBE52UNJ7MH4KY",
        # eid 不需要 要删掉
        # "fp": fp,  # 原始fp
        "fp": "6a2a3a3abb5f3faa2aac3bddaacfaadf",  # fp
        "jtb": gen_jd_shadow(),
        "o": "passport.jd.com/new/login.aspx",
        "oid": "",
        "p": "s",
        "pin": "",
        "qi": "",
        "qs": "",
        "t": get_jd_risk_token_id(),
        "v": "2.6.14.1",
    }
    return td_encrypt(param)


def get_eid():
    params = {
        "a": gen_eid_param()
    }
    data = {
        "g": gen_eid_data(),
        "d": ""
    }
    headers = {
        "User-Agent": user_agent,
        "Host": "gia.jd.com",
        "Referer": "https://passport.jd.com/",
        "Origin": "https://passport.jd.com",
    }
    resp = sess.post("https://gia.jd.com/fcf.html", params=params, data=data, headers=headers)
    return resp.text


def get_captcha(eid):
    url = "https://iv.jd.com/slide/g.html"
    headers = {
        "Host": "iv.jd.com",
        "Referer": "https://passport.jd.com/",
        "User-Agent": user_agent
    }
    params = {
        "appId": "1604ebb2287",
        "scene": "login",
        "product": "click-bind-suspend",
        "e": eid,
        "lang": "zh_CN",
        "callback": "jsonp_048506851392389594",
    }
    resp = sess.get(url, params=params, headers=headers)
    resp = resp.text[resp.text.find('{'):resp.text.rfind('}') + 1]
    resp = json.loads(resp)

    patch = resp["patch"]
    bg = resp["bg"]

    img = base64.b64decode(patch)
    file = open('patch.jpg', 'wb')
    file.write(img)
    file.close()

    img = base64.b64decode(bg)
    file = open('bg.jpg', 'wb')
    file.write(img)
    file.close()
    return resp["challenge"]


def get_diff_location():
    # 获取图片并灰度化
    block = cv2.imread("patch.jpg", 0)
    template = cv2.imread("bg.jpg", 0)
    # 二值化后的图片名称
    blockName = "block.jpg"
    templateName = "template.jpg"
    # 将二值化后的图片进行保存
    cv2.imwrite(blockName, block)
    cv2.imwrite(templateName, template)
    block = cv2.imread(blockName)
    block = cv2.cvtColor(block, cv2.COLOR_RGB2GRAY)
    block = abs(255 - block)
    cv2.imwrite(blockName, block)
    block = cv2.imread(blockName)
    template = cv2.imread(templateName)
    # 获取偏移量
    result = cv2.matchTemplate(block, template,
                               cv2.TM_CCOEFF_NORMED)  # 查找block在template中的位置，返回result是一个矩阵，是每个点的匹配结果
    x, y = np.unravel_index(result.argmax(), result.shape)
    print("distance:", y)
    # jd页面实际缩放图片，距离大约为图片距离的75%
    y = int(y * 0.77)
    print("distance_actually:", y)
    return y


def get_tracks(distance):
    trace = []
    faster_distance = distance * 3 / 5

    # 设置初始位置、初始速度、时间间隔
    start, v0, t = 0.0, 0.5, 0.2
    # 当尚未移动到终点时
    while start < distance:
        # 如果处于加速阶段
        if start < faster_distance:
            # 设置加速度为2
            a = round(random.uniform(0.5, 0.8), 2)
        # 如果处于减速阶段
        else:
            # 设置加速度为-3
            a = round(random.uniform(-0.7, -0.9), 2)
        # 移动的距离公式
        move = v0 * t + 1 / 2 * a * t * t
        move = int(move)
        # 此刻速度
        v = v0 + a * t
        # 重置初速度
        v0 = v
        # 重置起点
        start += move
        # 将移动的距离加入轨迹列表
        trace.append(round(move))
    # 返回轨迹信息
    return trace


def slide2(distance):
    def append_step(step_x, step_y, cost):
        global x,y,timestamp
        x += step_x
        y += step_y
        timestamp += cost
        res.append([x, y, timestamp])
    timestamp = get_timestamp()
    x, y = 733, 380
    res = [[702, 357, timestamp], [x, y, timestamp]]
    i = 0
    append_step(1, 0, random.randint(30, 100))
    append_step(1, 0, random.randint(5, 10))
    append_step(1, 0, random.randint(3, 5))
    while i < distance:



def slide(distance):
    template_dis = 136
    timestamp = get_timestamp()
    x, y = 733, 380
    step = "95,11,3,7,5,4,3,4,4,4,2,3,4,3,1,3,4,2,2,2,4,2,2,1,3,3,2,2,2,2,3,1,2,3,2,2,1,2," \
           "2,1,3,2,2,2,1,3,3,1,3,2,3,2,2,3,3,2,3,3,3,2,2,4,3,2,3,3,4,1,3,3,3,2,3,4,2,3,1," \
           "3,3,3,1,2,3,3,1,3,2,3,1,2,2,3,2,1,2,2,1,3,2,1,4,1,3,1,4,3,4,5,3,11,8,6,2,3,4," \
           "4,3,17,8,9,6,12,13,12,4,8,8,9,6,10,13,17,8,29,23,14".split(",")
    step = list(map(lambda s: int(s), step))

    l = len(step)
    check_pass_step = [18, 5, 18, 24, 19, 10, 131, 48, 102, 181, 14, 80, 13, 135]
    res = [
        [702, 357, timestamp],
        [733, 380, timestamp]
    ]

    relative = distance - template_dis
    adjust_time = template_dis // abs(relative)

    rm_offset = 0
    for i in range(1, abs(relative) + 1):
        idx = i * adjust_time
        if relative > 0:
            step.insert(idx, (step[idx - 1 - 1] + step[idx - 1]) // 2)
        else:
            step.pop(idx - rm_offset - 1)
            rm_offset += 1

    if len(step) != distance:
        print("len(step) not equal to distance, len(step): {}, distance: {}".format(len(step), distance))
        return

    change_y_count = 0
    change_y = random.randint(7, 11)
    i = 0
    total_time = 0
    while i < distance:
        x += 1
        if change_y_count >= change_y:
            y += 1 if random.randint(0, 1) == 0 else -1
            change_y = random.randint(7, 11)
            change_y_count = 0
        randtime = random.randint(0, 2)
        timestamp += step[i] + randtime
        total_time += step[i] + randtime
        res.append([x, y, timestamp])
        i += 1
        change_y_count += 1
    y += 1 if random.randint(0, 1) == 0 else -1
    s = [1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, 0, 0, 0]
    i = 0
    for time_step in check_pass_step:
        x += s[i]
        timestamp += time_step
        total_time += time_step
        res.append([x, y, timestamp])
        i += 1
    return res, total_time


def slide_encrypt(c):
    def st(d):
        c = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-~"
        b = len(c)
        e = d
        a = []

        # do...while
        mod = e % b
        e = (e - mod) // b
        a.insert(0, c[mod])
        while e:
            mod = e % b
            e = (e - mod) // b
            a.insert(0, c[mod])
        return "".join(a)

    def pm(d, c, b):
        e = st(abs(d))
        a = ""
        if not b:
            a += "1" if d > 0 else "0"

        def format_str(string, length):
            return ("0" * (length - 1) + string)[-length:]

        a += format_str(e, c)
        return a

    res = []
    for e in range(len(c)):
        if e == 0:
            res.append(pm(c[e][0] if c[e][0] < 262143 else 262143, 3, True))
            res.append(pm(c[e][1] if c[e][1] < 16777215 else 16777215, 4, True))
            res.append(pm(c[e][2] if c[e][2] < 4398046511103 else 4398046511103, 7, True))
        else:
            a = c[e][0] - c[e - 1][0]
            f = c[e][1] - c[e - 1][1]
            d = c[e][2] - c[e - 1][2]
            res.append(pm(a if a < 4095 else 4095, 2, False))
            res.append(pm(f if f < 4095 else 4095, 2, False))
            res.append(pm(d if d < 16777215 else 16777215, 4, True))
    return "".join(res)


def get_jdtdmap_session_id():
    url = "https://seq.jd.com/jseqf.html"
    headers = {
        "Host": "seq.jd.com",
        "Referer": "https://passport.jd.com/",
        "User-Agent": user_agent
    }
    params = {
        "bizId": "passport_jd_com_login_pc",
        "platform": "js",
        "version": 1,
    }
    resp = sess.get(url, params=params, headers=headers)
    session_id = resp.text.split(";")[0]
    return session_id[session_id.find("\"") + 1:-1]


def pass_slide_captcha(username, eid, jdtdmap_session_id, validate_id, distance):
    url = "https://iv.jd.com/slide/s.html"
    headers = {
        "Host": "iv.jd.com",
        "Referer": "https://passport.jd.com/",
        "User-Agent": user_agent
    }
    slide_data, total_time = slide(distance)
    time.sleep(total_time / 1000 + 1)
    param = {
        "d": slide_encrypt(slide_data),
        "c": validate_id,
        "w": 278,
        "appId": "1604ebb2287",
        "sence": "login",
        "product": "click-bind-suspend",
        "e": eid,
        "s": jdtdmap_session_id,
        "o": username,
        "lang": "zh_CN",
        "callback": "jsonp_07167088882048223",
    }

    resp = sess.get(url, params=param, headers=headers)
    print(resp.text)
    resp = json.loads(resp.text[resp.text.find("{"):resp.text.rfind("}") + 1])
    return False if resp["success"] == "0" else True


def login(username, password):
    url = "https://passport.jd.com/uc/loginService"
    headers = {
        "Host": "passport.jd.com",
        "Referer": "https://passport.jd.com/",
        "User-Agent": user_agent
    }


def test():
    resp = {
        "api_server": "//iv.jd.com/",
        "bg": "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",
        "challenge": "ee7fd477acad4f2cb2f5e20e0b8ceaa3",
        "message": "success",
        "o": "loginname",
        "patch": "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",
        "static_servers": "//ivs.jd.com/",
        "success": "1",
        "y": 66,
    }

    patch = resp["patch"]
    bg = resp["bg"]

    img = base64.b64decode(patch)
    file = open('patch.jpg', 'wb')
    file.write(img)
    file.close()

    img = base64.b64decode(bg)
    file = open('bg.jpg', 'wb')
    file.write(img)
    file.close()


def main():
    url = "https://passport.jd.com/new/login.aspx"
    sess.get(url, headers={"User-Agent": user_agent})
    eid = get_eid()
    sess_id = get_jdtdmap_session_id()
    success = False
    while not success:
        challenge = get_captcha(eid)
        distance = get_diff_location()
        success = pass_slide_captcha("123123", eid, sess_id, challenge, distance)
        time.sleep(0.5)


if __name__ == '__main__':
    main()
    # -----测试代码
    # test()
    # get_diff_location()
    # 79 --- 60
    # 168 --- 130
    # 80 --- 62
    # a = [["702","342",1616343302901],["736","365",1616343302901],["737","365",1616343302967],["738","365",1616343302979],["739","365",1616343302986],["740","365",1616343302990],["741","365",1616343302996],["742","365",1616343302999],["742","366",1616343303001],["743","366",1616343303002],["744","366",1616343303007],["745","366",1616343303011],["746","366",1616343303014],["747","367",1616343303017],["748","367",1616343303022],["749","367",1616343303025],["750","368",1616343303027],["751","368",1616343303029],["752","368",1616343303032],["753","368",1616343303035],["754","368",1616343303036],["755","368",1616343303039],["756","368",1616343303042],["756","369",1616343303043],["757","369",1616343303045],["758","369",1616343303046],["759","369",1616343303049],["760","369",1616343303051],["761","369",1616343303054],["762","369",1616343303055],["763","369",1616343303058],["764","369",1616343303061],["765","369",1616343303064],["766","369",1616343303065],["767","369",1616343303068],["768","369",1616343303071],["769","369",1616343303074],["770","369",1616343303075],["771","369",1616343303078],["772","369",1616343303081],["772","370",1616343303082],["773","370",1616343303083],["774","370",1616343303088],["775","370",1616343303091],["776","370",1616343303097],["777","370",1616343303107],["778","370",1616343303116],["779","370",1616343303118],["780","370",1616343303125],["781","370",1616343303129],["782","370",1616343303131],["783","370",1616343303133],["784","371",1616343303136],["785","371",1616343303138],["786","371",1616343303142],["787","371",1616343303143],["788","371",1616343303147],["789","371",1616343303152],["789","372",1616343303156],["790","372",1616343303158],["791","372",1616343303161],["792","372",1616343303167],["793","372",1616343303173],["794","372",1616343303179],["795","372",1616343303182],["796","372",1616343303190],["797","372",1616343303198],["798","372",1616343303205],["799","372",1616343303209],["800","372",1616343303215],["801","372",1616343303221],["802","372",1616343303226],["803","373",1616343303232],["804","373",1616343303235],["805","373",1616343303241],["806","373",1616343303248],["807","373",1616343303254],["808","373",1616343303257],["808","374",1616343303260],["809","374",1616343303265],["810","374",1616343303276],["809","374",1616343303478],["808","374",1616343303493],["807","374",1616343303502],["806","374",1616343303527],["806","375",1616343303544],["805","375",1616343303592],["804","375",1616343303685],["803","375",1616343303699],["802","375",1616343303719],["801","375",1616343303737],["800","375",1616343303773],["799","375",1616343303836],["798","375",1616343303851],["798","375",1616343304072]]
    # for i in a:
    #     i[0] = int(i[0])
    #     i[1] = int(i[1])
    # print(slide_encrypt(a))
