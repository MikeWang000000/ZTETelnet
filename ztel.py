#!/usr/bin/env python
# -*- coding: utf-8 -*-
import array
import random
import argparse
import binascii
try:
    import urllib.request as urlreq
    import urllib.parse as urlparse
    from urllib.error import HTTPError
except ImportError:
    import urllib2 as urlreq
    from urllib2 import urlparse
    from urllib2 import HTTPError
    from httplib import BadStatusLine as ConnectionError


def main():
    parser = argparse.ArgumentParser(description='Turn on Telnet service of a ZTE router or ONU.')
    parser.add_argument("-s", action="store_true", help="stop Telnet service")
    parser.add_argument("-u", type=str, metavar="<user>", default=None, help="username of ZTE router")
    parser.add_argument("-p", type=str, metavar="<pass>", default=None, help="password of ZTE router")
    parser.add_argument(
        "address", nargs="?", type=str, metavar="address", default="192.168.1.1",
        help="ZTE router IP address, default is 192.168.1.1"
    )
    args = parser.parse_args()
    base_url = "http://" + args.address
    if args.u and args.p:
        userpass = ((args.u, args.p),)
    else:
        userpass = (
            ("factorymode", "nE%jA@5b"),
            ("CMCCAdmin", "aDm8H%MdA"),
            ("CUAdmin", "CUAdmin"),
            ("telecomadmin", "nE7jA%5m"),
            ("cqadmin", "cqunicom"),
            ("user", "1620@CTCC"),
            ("admin", "1620@CUcc"),
            ("cuadmin", "admintelecom"),
            ("lnadmin", "cuadmin"),
            ("useradmin", "lnadmin")
        )
    success = False
    for u, p in userpass:
        try:
            ztel = ZTETelnet(u, p, base_url)
            if args.s:
                ztel.close_telnet()
                print("Telnet service stopped.")
            else:
                username, password = ztel.open_telnet()
                print("Telnet service started.")
                print("")
                print("Username: %s" % username)
                print("Password: %s" % password)
            success = True
            break
        except ZTETelnet.InvalidUserPass:
            continue
    if not success:
        raise ZTETelnet.InvalidUserPass("Invalid username or password")


class ZTETelnet(object):
    _aes_key_ver1 = array.array('B', binascii.unhexlify(
        "7b56b0f7da0e6852c819f32b849079e562f8ead2649387df73d7fbccaafe7543"
        "1c29df4c522c6e7b453d1ff1debc27858a4591be3813de673208541175f4d3b4"
        "a4b312866723994c617fb1d230df47f17693a38c95d359bf878ef3b3e4764988"
    ))
    _aes_key_ver2 = array.array('B', binascii.unhexlify(
        "8c2365d1fc324537112871630720691473e7d453132436c2b5e1fccf8a9a4189"
        "3c49cf5c728c9eeb750d3fd1fecc57657a35213e68537e970248747195345384"
        "b4c3e2d6273de65d729cbc3d03fd76c19c25a89247e4180f243f4f67ec97f499"
    ))

    class UnrecognizedProtocol(Exception):
        pass

    class InvalidUserPass(Exception):
        pass

    def __init__(self, username, password, base_url="http://192.168.1.1"):
        self.opener = urlreq.build_opener(
            urlreq.HTTPCookieProcessor(),
            urlreq.ProxyHandler({})
        )
        self.username = username
        self.password = password
        self.base_url = base_url
        self.cipher = None

    def pad(self, data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad) % block_size
        return data_to_pad + b"\0" * padding_len

    def unpad(self, padded_data, block_size):
        return padded_data[:-block_size] + padded_data[-block_size:].rstrip(b"\0")

    def reset(self):
        try:
            self.opener.open(self.base_url + "/webFac", data=b"SendSq.gch")
        except HTTPError:
            pass

    def request_factory_mode(self):
        try:
            self.opener.open(self.base_url + "/webFac", data=b"RequestFactoryMode.gch")
        except ConnectionError:
            pass

    def send_sq(self):
        rand = random.randint(0, 59)
        try:
            res = self.opener.open(self.base_url + "/webFac", data=b"SendSq.gch?rand=%d\r\n" % rand)
        except ConnectionError:
            raise ZTETelnet.UnrecognizedProtocol
        data = res.read()
        if len(data) == 0:
            version = 1
            index = rand
            key_pool = self._aes_key_ver1
        elif b"newrand" in data:
            version = 2
            newrand = int(data[len(b"newrand="):])
            index = ((0x1000193 * rand) & 0x3F ^ newrand) % 60
            key_pool = self._aes_key_ver2
        else:
            raise ZTETelnet.UnrecognizedProtocol
        key_arr = array.array(
            'B', map(lambda x: (x ^ 0xA5) & 0xFF, key_pool[index:index+24])
        )
        if hasattr(key_arr, "tobytes"):
            key = array.array('B', key_arr).tobytes()
        else:
            key = array.array('B', key_arr).tostring()
        self.cipher = AESModeECB(key)
        return version

    def send_info(self):
        try:
            self.opener.open(
                self.base_url + "/webFacEntry",
                data=self.cipher.encrypt(self.pad(b"SendInfo.gch?info=6|", 16))
            )
        except ConnectionError:
            raise ZTETelnet.UnrecognizedProtocol

    def check_login_auth(self, username, password):
        try:
            res = self.opener.open(
                self.base_url + "/webFacEntry",
                data=self.cipher.encrypt(
                    self.pad(("CheckLoginAuth.gch?version50&user=%s&pass=%s" % (username, password)).encode(), 16)
                ))
        except HTTPError as ex:
            if ex.code == 401:
                return None
            else:
                raise ex
        except ConnectionError:
            raise ZTETelnet.UnrecognizedProtocol
        ciphertext = res.read()
        if len(ciphertext) % 16:
            ciphertext = self.pad(ciphertext, 16)
            url = self.unpad(self.cipher.decrypt(ciphertext), 16)
            return url
        return None

    def factory_mode(self, mode=2):
        # factory_mode 0:close 1:ops 2:dev 3:production 4:user
        try:
            if not mode:
                res = self.opener.open(
                    self.base_url + "/webFacEntry",
                    data=self.cipher.encrypt(self.pad(b'FactoryMode.gch?close', 16))
                )
            else:
                res = self.opener.open(
                    self.base_url + "/webFacEntry",
                    data=self.cipher.encrypt(self.pad(b'FactoryMode.gch?mode=%d&user=notused' % mode, 16))
                )
        except ConnectionError:
            raise ZTETelnet.UnrecognizedProtocol

        # excepted data: b"FactoryModeAuth.gch?user=<telnet_user>&pass=<telnet_pass>\0"
        data = res.read()
        url = self.unpad(self.cipher.decrypt(data), 16).rstrip(b"\0").decode()
        query = urlparse.urlparse(url).query
        qdict = urlparse.parse_qs(query)
        try:
            telnet_user = qdict['user'][0]
            telnet_pass = qdict['pass'][0]
            return telnet_user, telnet_pass
        except KeyError:
            return None, None

    def open_telnet(self, mode=2):
        telnet_user = telnet_pass = None
        self.reset()
        self.request_factory_mode()
        version = self.send_sq()
        if version > 1:
            self.send_info()
        if self.check_login_auth(self.username, self.password):
            return self.factory_mode(mode)
        else:
            raise ZTETelnet.InvalidUserPass

    def close_telnet(self):
        self.open_telnet(mode=0)


# Pure Python implementation for ECB Mode of AES.
# Modified from https://bitbucket.org/intgr/pyaes/
# Copyright (c) 2010 Marti Raudsepp <marti@juffo.org>
# Licensed under the MIT License

class AESModeECB(object):
    def __init__(self, key):
        self.cipher = AES(key)
        self.block_size = self.cipher.block_size

    def _ecb(self, data, block_func):
        if len(data) % self.block_size != 0:
            raise ValueError("Input length must be multiple of 16")
        if type(data) is not bytes:
            data = data.encode()
        block_size = self.block_size
        data = array.array('B', data)
        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            block_func(block)
            data[offset:offset + block_size] = block
        if hasattr(data, "tobytes"):
            return data.tobytes()
        else:
            return data.tostring()

    def encrypt(self, data):
        return self._ecb(data, self.cipher.encrypt_block)

    def decrypt(self, data):
        return self._ecb(data, self.cipher.decrypt_block)


class AESUtils(object):
    @staticmethod
    def _galois_multiply(a, b):
        p = 0
        while b:
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x1b
            b >>= 1
        return p & 0xff


class AES(object):
    block_size = 16
    _aes_sbox = array.array('B', binascii.unhexlify(
        '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
        'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
        '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
        'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
        'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
        'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
        'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
        'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
    ))
    _aes_inv_sbox = array.array('B', binascii.unhexlify(
        '52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb'
        '547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125'
        '72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84'
        '90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b'
        '3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e'
        '47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4'
        '1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef'
        'a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d'
    ))
    _aes_Rcon = array.array('B', binascii.unhexlify(
        '8d01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc59139'
        '72e4d3bd61c29f254a943366cc831d3a74e8cb8d01020408102040801b366cd8'
        'ab4d9a2f5ebc63c697356ad4b37dfaefc5913972e4d3bd61c29f254a943366cc'
        '831d3a74e8cb8d01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b3'
        '7dfaefc5913972e4d3bd61c29f254a943366cc831d3a74e8cb8d010204081020'
        '40801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc5913972e4d3bd61c29f'
        '254a943366cc831d3a74e8cb8d01020408102040801b366cd8ab4d9a2f5ebc63'
        'c697356ad4b37dfaefc5913972e4d3bd61c29f254a943366cc831d3a74e8cb'
    ))

    _gf_mul_by_2 = array.array('B', [AESUtils._galois_multiply(x, 2) for x in range(256)])
    _gf_mul_by_3 = array.array('B', [AESUtils._galois_multiply(x, 3) for x in range(256)])
    _gf_mul_by_9 = array.array('B', [AESUtils._galois_multiply(x, 9) for x in range(256)])
    _gf_mul_by_11 = array.array('B', [AESUtils._galois_multiply(x, 11) for x in range(256)])
    _gf_mul_by_13 = array.array('B', [AESUtils._galois_multiply(x, 13) for x in range(256)])
    _gf_mul_by_14 = array.array('B', [AESUtils._galois_multiply(x, 14) for x in range(256)])

    def __init__(self, key):
        self.setkey(key)

    def setkey(self, key):
        if type(key) is not bytes:
            self.key = key.encode()
        else:
            self.key = key
        self.key_size = len(key)
        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError("Key length must be 16, 24 or 32 bytes")
        self._expand_key()

    def _expand_key(self):
        exkey = array.array('B', self.key)
        if self.key_size == 16:
            extra_cnt = 0
        elif self.key_size == 24:
            extra_cnt = 2
        else:
            extra_cnt = 3
        word = exkey[-4:]
        for i in range(1, 11):
            word = word[1:4] + word[0:1]
            for j in range(4):
                word[j] = AES._aes_sbox[word[j]]
            word[0] ^= AES._aes_Rcon[i]
            for z in range(4):
                for j in range(4):
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)
            if len(exkey) >= (self.rounds + 1) * self.block_size:
                break
            if self.key_size == 32:
                for j in range(4):
                    word[j] = AES._aes_sbox[word[j]] ^ exkey[-self.key_size + j]
                exkey.extend(word)
            for z in range(extra_cnt):
                for j in range(4):
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)
        self.exkey = exkey

    def _add_round_key(self, block, round):
        offset = round * 16
        exkey = self.exkey
        for i in range(16):
            block[i] ^= exkey[offset + i]

    def _sub_bytes(self, block, sbox):
        for i in range(16):
            block[i] = sbox[block[i]]

    def _shift_rows(self, b):
        b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
        b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]

    def _shift_rows_inv(self, b):
        b[5], b[9], b[13], b[1] = b[1], b[5], b[9], b[13]
        b[10], b[14], b[2], b[6] = b[2], b[6], b[10], b[14]
        b[15], b[3], b[7], b[11] = b[3], b[7], b[11], b[15]

    def _mix_columns(self, block):
        mul_by_2 = AES._gf_mul_by_2
        mul_by_3 = AES._gf_mul_by_3
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]
            block[col] = mul_by_2[v0] ^ v3 ^ v2 ^ mul_by_3[v1]
            block[col + 1] = mul_by_2[v1] ^ v0 ^ v3 ^ mul_by_3[v2]
            block[col + 2] = mul_by_2[v2] ^ v1 ^ v0 ^ mul_by_3[v3]
            block[col + 3] = mul_by_2[v3] ^ v2 ^ v1 ^ mul_by_3[v0]

    def _mix_columns_inv(self, block):
        mul_9 = AES._gf_mul_by_9
        mul_11 = AES._gf_mul_by_11
        mul_13 = AES._gf_mul_by_13
        mul_14 = AES._gf_mul_by_14
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col:col + 4]
            block[col] = mul_14[v0] ^ mul_9[v3] ^ mul_13[v2] ^ mul_11[v1]
            block[col + 1] = mul_14[v1] ^ mul_9[v0] ^ mul_13[v3] ^ mul_11[v2]
            block[col + 2] = mul_14[v2] ^ mul_9[v1] ^ mul_13[v0] ^ mul_11[v3]
            block[col + 3] = mul_14[v3] ^ mul_9[v2] ^ mul_13[v1] ^ mul_11[v0]

    def encrypt_block(self, block):
        self._add_round_key(block, 0)
        for round in range(1, self.rounds):
            self._sub_bytes(block, AES._aes_sbox)
            self._shift_rows(block)
            self._mix_columns(block)
            self._add_round_key(block, round)
        self._sub_bytes(block, AES._aes_sbox)
        self._shift_rows(block)
        self._add_round_key(block, self.rounds)

    def decrypt_block(self, block):
        self._add_round_key(block, self.rounds)
        for round in range(self.rounds - 1, 0, -1):
            self._shift_rows_inv(block)
            self._sub_bytes(block, AES._aes_inv_sbox)
            self._add_round_key(block, round)
            self._mix_columns_inv(block)
        self._shift_rows_inv(block)
        self._sub_bytes(block, AES._aes_inv_sbox)
        self._add_round_key(block, 0)


if __name__ == '__main__':
    main()
