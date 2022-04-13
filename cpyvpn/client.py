# -*- coding: utf-8 -*-
# Created on 07.05.2021
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import os.path as op
import time
import datetime

import asyncio
import logging
import secrets
import contextlib
import subprocess

import argparse

from . import utils
from . import ssl_ctx
from . import cui
from . import auth
from . import vna
from . import cfg
from . import snx

logger = logging.getLogger()


# From https://gist.github.com/akaIDIOT/48c2474bd606cd2422ca
def call_periodic(interval, callback):
    loop = asyncio.get_running_loop()
    # record the loop's time when call_periodic was called
    start = loop.time()

    def run(handle):
        # XXX: we could record before = loop.time() and warn when callback(*args) took longer than interval
        # call callback now (possibly blocks run)
        callback()
        # reschedule run at the soonest time n * interval from start
        # re-assign delegate to the new handle
        handle.delegate = loop.call_later(interval - ((loop.time() - start) % interval), run, handle)

    class PeriodicHandle:  # not extending Handle, needs a lot of arguments that make no sense here

        def __init__(self):
            self.delegate = None

        def cancel(self):
            assert isinstance(self.delegate, asyncio.Handle), 'no delegate handle to cancel'
            self.delegate.cancel()

    periodic = PeriodicHandle()  # can't pass result of loop.call_at here, it needs periodic as an arg to run
    # set the delegate to be the Handle for call_at, causes periodic.cancel() to cancel the call to run
    periodic.delegate = loop.call_at(start + interval, run, periodic)
    # return the 'wrapper'
    return periodic


class SNXHandler(snx.SNX):
    DISC_msg = cfg.CPRR({"disconnect":{"code":28, "message":"User has disconnected."}}).serialize()
    _ver_spec2 = {
                "client_version":2,
                "protocol_version":2
            }
    _ver_spec11 = {
                "client_version":1,
                "protocol_version":1,
                "protocol_minor_version":1
            }

    def __init__(self, vna, cookie, version, range_list):
        self.vna = vna
        self.vna_fd = None
        self.cookie = cookie
        self.ver = version
        self.range_list = range_list
        self._ka_handle = None
        self._hr = None

        super(SNXHandler, self).__init__(vna)

    def keepalive(self, rr):
        # ping back - do nothing
        pass

    def hello_reply(self, rr):

        reply = rr
        hr = reply.find("hello_reply")
        if hr is None:
            raise IOError("Bad hello reply")
        hr_prev = dict(self._hr) if self._hr else {}
        hr_prev.pop("optional", None)

        hr_cur = dict(hr)
        hr_cur.pop("optional")

        if hr_prev == hr_cur:
            return
        self._hr = hr
        logger.debug("Recieved reply: {}".format(hr))

        # Timeouts:
        self._keepalive = int(hr['timeouts']["keepalive"])
        self._auth_time = max(3600, int(hr['timeouts']["authentication"]))
        self._keepalive = max(self._keepalive , 5)
        self._auth_end = self._auth_time - self._keepalive + time.time()

        gw_ip = self.transport.get_extra_info('peername')[0]

        gw_ipint = utils.ipstr2int(gw_ip)
        route_list = []

        for itm in hr.get("range", self.range_list):
            ipfrm = itm ["from"]
            ipto = itm ["to"]
            ipf = utils.ipstr2int(ipfrm)
            ipt = utils.ipstr2int(ipto)
            if ipf == ipt:
                if gw_ipint == ipf:
                    continue
                route_list.append((ipfrm,))
            else:
                route_list.append((ipfrm, ipto))

        selfip = hr[ "OM"]["ipaddr"]

        dns = hr[ "OM"].get("dns_servers", [])
        dns_suffix = hr[ "OM"]["dns_suffix"]
        # VNA stuff
        logger.info("Configuring vna.")
        self.vna.set_routes(route_list)
        self.vna.set_dns(dns)
        self.vna.set_dns_suffix(dns_suffix)
        self.vna.set_ips(selfip, gw_ip)
        self.vna.up()

        loop = asyncio.get_running_loop()
        if self.vna_fd is not  None:
            loop.remove_reader(self.vna_fd)
        self.vna_fd = self.vna.dev.fileno()
        loop.add_reader(self.vna_fd, self.send_vna_packet)

        self.send_cmd(self.KA_msg)  # INITIAL KA

        logger.info("IP: {}".format(selfip))
        dns_list = ",".join(dns)
        if dns_list:
            logger.info("DNS: {}".format(dns_list))
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=self._auth_time)
        logger.info("Timeout: {} hours, will expire around {}.".format(self._auth_time // (3600), expires_at.isoformat(str(' '))))

        KA_int = self._keepalive
        self._ka_handle = call_periodic(KA_int, self.send_keepalive)

    def disconnect(self, reply):
        logger.error("Recieved disconnect from server: code={}, message='{}'.".format(reply.find("code"), reply.find("message")))
        loop = asyncio.get_running_loop()
        loop.stop()

    def send_client_hello(self):

        ver = self.ver

        if ver == 2:
            ver_spec = self._ver_spec2
        elif ver == 1:
            ver_spec = self._ver_spec11
        else:
            raise NotImplementedError("version={}".format(ver))

        cmd_hello = {}
        cmd_hello.update(ver_spec)

        if self.vna.om_ip() is None:
            om = {"ipaddr":"0.0.0.0", "keep_address":"false"}
        else:
            om = {"ipaddr":self.vna.addr, "keep_address":"true"}

        cmd_hello["OM"] = om

        opt = {"client_type":4}

        cmd_hello["optional"] = opt

        full_cmd = {"client_hello":cmd_hello}
        cmd_hello["cookie"] = "X"
        logger.debug("Sending hello: {}".format(cfg.CPRR(full_cmd).serialize()[:-1]))
        cmd_hello["cookie"] = self.cookie

        self.send_cmd(cfg.CPRR(full_cmd).serialize())

        self.reconnect = False

    def send_keepalive(self):
        self.send_cmd(self.KA_msg)

    def send_disconnect(self):

        if self._ka_handle:
            self._ka_handle.cancel()
        self.send_cmd(self.DISC_msg)

    def send_vna_packet(self):
        data = self.vna.tundev().read()
        if data is not None:
            self.send_packet(data)

    def on_connection_lost(self, exc):
        self.reconnect = True
        if self._ka_handle:
            self._ka_handle.cancel()
        loop = asyncio.get_running_loop()
        loop.stop()


def get_ranges(url, sid):
    body = '''(CCCclientRequest
    :RequestHeader (
        :id (3)
        :session_id ({})
        :type (ClientSettings)
        :protocol_version (100)
    )
    :RequestData (ClientSettings
        :requested_policies_and_current_versions (
            :range ()
            :nemo_client_1 ()
        )
    )
)
'''.format(sid)
    ret = utils.do_ccc_request(url + "/clients/", data=body)
    rd = ret.find("ResponseData")
    range_list = rd.get("updated_policies", {}).get("range", {}).get("settings", [])
    return range_list


def get_esp_setup(url, sid):
    spi = "0x" + secrets.token_hex(4)
    body = '''(CCCclientRequest
    :RequestHeader (
        :id (4)
        :session_id ({})
        :type (KeyManagement)
        :protocol_version (100)
    )
    :RequestData (
        :SPI ({})
        :rekey (false)
        :req_om_addr (0x00000000)
    )
)
'''.format(sid, spi)
    ret = utils.do_ccc_request(url + "/clients/", data=body)


def snx_main(options):
    with contextlib.closing(auth.SNXAuth(options, options.ui)) as sna:

        if options.mode == 'q':
            return
        sna.init()
        slim_ver = 1
        rl = []
        # Use slim protocol v2 if NOT MA
        if not options.force_v1 and not sna.use_ma and sna.gw_info.pv >= 100:
            slim_ver = 2
            rl = get_ranges(sna.auth_obj.url, sna.auth_obj.sid)
            if options.transport != "ssl":
                get_esp_setup(sna.auth_obj.url, sna.auth_obj.sid)
                return

        vna_obj = options.vna_obj

        sd = sna.get_session_data()
        if options.printcookie:
            if sna.use_ma:
                cookie_str = sna.auth_obj.ma_cookies
            else:
                cookie_str = "{}:{}".format(sna.auth_obj.sid, sd.cookie)
            logger.info("COOKIE: {}".format(cookie_str))

        try:
            loop = asyncio.get_event_loop()
            coro = loop.create_connection(lambda: SNXHandler(vna_obj, sd.cookie, slim_ver, rl), \
                                               host=sd.host, port=sd.port, ssl=ssl_ctx.get_ssl_context())
            transport, prot = loop.run_until_complete(coro)
            prot.send_client_hello()
            loop.run_forever()
        except KeyboardInterrupt:
            logger.debug("KeyboardInterrupt")
            prot.send_disconnect()

        logger.debug("Closing everything")

        transport.close()
        loop.close()


def manage_cert(options):
    out = options.user_cert
    ui = options.ui

    if not out:
        raise ValueError("Certificate file name required! Use --user_cert to set the name.")

    if op.exists(out):
        if out == options.rc:
            raise IOError("File names for old and new certificate are the same. This is not supported!")
        repl = ui.ask_str("File {} exists. Overwrite [y/n]?".format(out))
        if not repl or repl.lower()[0] != "y":
            return

    def get_cert_data():
        if not options.rc:
            regkey = ui.ask_str("Enrollment key (from email)")
            if not regkey:
                raise RuntimeError("Key must not be empty!")
            if len(regkey) >= 64:
                raise RuntimeError("Key too long!")

        ask_pwd = "your certificate password"
        pwd1 = ui.ask_pwd("Enter " + ask_pwd)
        pwd2 = ui.ask_pwd("Confirm " + ask_pwd)
        if pwd1 != pwd2:
            raise RuntimeError("Entered passwords do NOT match!")
        if len(pwd1) >= 64:
                raise RuntimeError("Password too long!")

        if options.rc:
            with open(options.rc, "rb") as f:
                binary = f.read()
            binary_enc = bytes(reversed(binary)).hex()
            EnrollmentRequest = '''(CCCclientRequest
        :RequestHeader (
            :id (1)
            :session_id ()
            :type (CertRenewalRequest)
            :protocol_version (100)
        )
        :RequestData (
            :binary ({})
            :password ({})
        )
    )\x00'''.format(binary_enc, auth.enc(pwd1))
        else:
            EnrollmentRequest = '''(CCCclientRequest
        :RequestHeader (
            :id (1)
            :session_id ()
            :type (CertEnrollmentRequest)
            :protocol_version (100)
        )
        :RequestData (
            :regkey ({})
            :password ({})
            :device_type ("")
            :device_id ()
            :device_name ("")
        )
    )\x00'''.format(auth.enc(regkey), auth.enc(pwd1))

        p = utils.parseurl(options.server)
        ssl_ctx.check_ssl_mode(p.host, p.port, options.nocert)
        ret = utils.do_ccc_request(options.server + "/clients", EnrollmentRequest)

        ec = int(ret.find("error_code"))
        if ec != 0:
            raise RuntimeError("Certificate retrieval failed, code {}.".format(ec))
        data = ret.find("binary")

        return auth.dec(data, unscramble=False), pwd1

    # try to write some random bytes in output file to 'reserve' space for incoming data
    # If we fetch cert, but can't write it cert will be lost and a new one have to be issued
    try:
        f = open(out, "wb")
        f.write(secrets.token_bytes(8 * 1024))
        f.seek(0)
        bindata, pwd = get_cert_data()
    except:
        os.unlink(out)
        raise

    f.truncate(len(bindata))
    f.write(bindata)
    f.close()

    outpem = op.splitext(out)[0] + ".pem"
    cmdl = ["openssl", "pkcs12", "-in", out, "-out", outpem, "-passin", "stdin", "-passout", "stdin"]
    rc = subprocess.run(cmdl, input=utils.as_bytes("{0}\n{0}\n".format(pwd))).returncode
    if rc == 0:
        logger.info("PEM file '{}' ready, do not delete {} if you plan to renew it.".format(outpem, out))
    else:
        logger.info("openssl failed, convert  manually using command '{}'.".format(" ".join(cmdl[:-4])))


def main():
    parser = argparse.ArgumentParser(description="CheckPoint VPN client.")
    parser.add_argument("server", default="", type=str, help="Gateway server address with optional port.")  # host or host:port or https://host:port
    parser.add_argument("-m", "--mode", default="a", type=str, help="a(uto), l(ogin+password), m(obile), p(inpad), k(eyfob), h(challenge)")
    utils.add_common_client_args(parser)
    parser.add_argument("--printcookie", action='store_true', default=False, help="Print cookie before connecting.")
    parser.add_argument("--force_v1", action='store_true', default=False, help="Force previous SLIM protocol version.")
    parser.add_argument("--force_logout", action='store_true', default=False, help="Logout from MAP session even when browser cookie is used.")
    parser.add_argument("-t", "--transport", default="ssl", type=str, help="Transport to use: ssl or esp.")
    parser.add_argument("--ct", default="TRAC", type=str, help="Client type: TRAC, SYMBIAN, etc.")
    parser.add_argument("-i", "--interface", type=str, help="Use given name for tunnel interface instead of default one.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", "--script-tun", dest="script_tun", type=str, help="Pass traffic to 'script' program, instead of tun.")
    group.add_argument("-s", "--script", type=str, help="Shell command line for using a vpnc-compatible config script.")

    # Certificate  enrollment support
    parser.add_argument("--enroll", action='store_true', default=False, help="Set enrollment key.")
    parser.add_argument("--rc", type=str, help="P12 certificate file to renew.")

    utils.add_common_args(parser)
    options = parser.parse_args()
    options.ui = cui.TUI()

    if options.enroll or options.rc:
        utils.setup_loglevel(options)
        manage_cert(options)
        return

    if options.user_cert:
        options.mode = 'c'

    utils.client_setup(options)

    args = {}
    for k in ["interface", "script", "script_tun"]:
        v = getattr(options, k)
        if v:
            args[k] = v
    with vna.init_vna(args) as  vna_obj:
        options.vna_obj = vna_obj
        snx_main(options)


if __name__ == '__main__':
    main()
