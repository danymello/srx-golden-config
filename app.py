import web, string, random, subprocess, sys, pycurl, pprint, json, re
from io import BytesIO
from flask import Flask, request, render_template, send_from_directory
import datetime
from jinja2 import Environment, FileSystemLoader
import logging
import time

start_time = time.asctime( time.localtime(time.time()) )


### functions


def init_logger():
  """
  Setup the logger.
  write logs in /var/log/srx-gen.log
  """

  logging.basicConfig(filename='/var/log/srx-gen.log',
                      level = logging.INFO,
                      format='%(asctime)s %(levelname)-8s %(message)s',
                      datefmt='%a, %d %b %Y %H:%M:%S')
  logger = logging.getLogger(__name__)

  return logger

def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
	"""
  	This function will generate a random ID and return it.
  	"""

	return ''.join(random.choice(chars) for _ in range(size))

def CollectHTMLForm(deployment, request):
  	"""
  	This function will collect all the parameters from the HTML form
  	it will return a dict.
  	"""

	vars = {}

	logger.info("Starting the parsing of the HTMP form. Deployment is %s" % deployment)

	#print "DEPLOYMENT"+typedep
	vars.update({'dep': request.form['deployment']})

	# network	
	vars.update({'trust_int': request.form['TrustInterface']})
	vars.update({'untrust_int': request.form['UntrustInterface']})
	
	if deployment == "Routed":

		vars.update({'trust_ip': request.form['TrustIP']})
		vars.update({'untrust_ip': request.form['UntrustIP']})
	
	elif deployment == "Sniffer":

		vars.update({'sniffer_int': request.form['SnifferInterface']})
		#physical interface
		interface_phy = vars.get('sniffer_int').split(".")
		vars.update({'sniffer_int_phy': interface_phy})


	
	vars.update({'mgmt_int': request.form['MgmtInterface']})
	vars.update({'mgmt_ip': request.form['MgmtIP']})
	vars.update({'mgmt_gw': request.form['MgmtGW']})
	vars.update({'log_local': request.form['log_local']})

	#UTM
	vars.update({'ewf': request.form['ewf']})
	vars.update({'avv': request.form['avv']})
	vars.update({'aspam': request.form['as']})


	#AppSecure
	vars.update({'apptrack': request.form['apptrack']})
	if deployment != "Sniffer":
		vars.update({'appfw': request.form['appfw']})

	#IDP
	vars.update({'idp': request.form['idp']})
	if deployment != "Sniffer":
		vars.update({'idp_action': request.form['idp_action']})
	vars.update({'idp_mode': request.form['idp_mode']})
	vars.update({'bypass_idp': request.form['bypass_idp']})
	
	#SkyATP
	vars.update({'aamw': request.form['aamw']})
	if deployment != "Sniffer":
		if request.form.get('aamw_log_only') == 'on':
			vars.update({'aamw_log_only': request.form['aamw_log_only']})
		else:
			vars.update({'aamw_threshold': request.form['aamw_threshold']})
	
	#secintel CC
	vars.update({'secintel_cc_ip': request.form['secintel_cc_ip']})
	if deployment != "Sniffer":
		vars.update({'secintel_cc_url': request.form['secintel_cc_url']})
		vars.update({'secintel_blocklist': request.form['secintel_blocklist']})
		vars.update({'secintel_dshield': request.form['secintel_dshield']})
		vars.update({'secintel_maldom': request.form['secintel_maldom']})
		vars.update({'secintel_ransom': request.form['secintel_ransom']})
		vars.update({'secintel_tor': request.form['secintel_tor']})

	# value is set to None/Null when box is uncheck. otherwise, it is set to true.
	if deployment != "Sniffer":
		block_msg = request.form.get('secintel_block_msg')
		if block_msg:
			vars.update({'secintel_block_msg': request.form['secintel_block_msg']})

	
	#secintel Infected Hosts
	vars.update({'secintel_infhosts': request.form['secintel_infhosts']})

	#SSL
	vars.update({'sslfp': request.form['sslfp']})
	vars.update({'bypass_sslfp': request.form['bypass_sslfp']})
	#vars.update({'sslp': request.form['sslp']})

	#UserID
	vars.update({'DCIP': request.form['DCIP']})
	vars.update({'DomainName': request.form['DomainName']})
	vars.update({'Username': request.form['Username']})
	vars.update({'Password': request.form['Password']})

	len_vars = len(vars)
	logger.info("Number of item in the dict %d" % len_vars)

	return vars


def BuildConfigurationJinja2(v):
	"""
  	This function will generate all part of the configuration based on jinja2 templates located in folder "junos-templates". 
  	all output for each template will be concatenate and returned. 
  	Return valus is a string.
  	"""

  	logger.info("Building the configuration blocks")

	#j2_env = Environment(loader=FileSystemLoader('junos-templates'),trim_blocks=True,lstrip_blocks=True,extensions=['jinja2.ext.loopcontrols'])
	j2_env = Environment(loader=FileSystemLoader('junos-templates'),extensions=['jinja2.ext.loopcontrols'])
	template  = j2_env.get_template('srx-base.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-base.j2")
	concatenate_output = outputblob
	template  = j2_env.get_template('srx-utm.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-utm.j2")
	concatenate_output += outputblob
	template  = j2_env.get_template('srx-idp.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-utm.j2")
	concatenate_output += outputblob
	template  = j2_env.get_template('srx-appsecure.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-appsecure.j2")
	concatenate_output += outputblob
	template  = j2_env.get_template('srx-skyatp.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-skyatp.j2")
	concatenate_output += outputblob
	template  = j2_env.get_template('srx-ssl.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-ssl.j2")
	concatenate_output += outputblob
	template  = j2_env.get_template('srx-userfw.j2')
	outputblob = template.render(v=v)
	logger.info("Generating configuration for template srx-userfw.j2")
	concatenate_output += outputblob
	logger.info("Configuration done.")

	#print(repr(concatenate_output))
	
	final_output = concatenate_output.replace("\t", "")

	#print final_output

	return final_output


########
### App
########

app = Flask(__name__)


### URL handling

@app.route('/', methods=['GET','POST'])
def root():

	return render_template('index.html')


@app.route('/download/<path:path>')
def download(path):
	return send_from_directory('conf', path, as_attachment=True)


@app.route('/l3',methods=['GET','POST'])
def l3():
  
  if request.method == 'POST':
	
  	logger.info("L3 has been selected. let's generate the config")

	vars={}

	#Collecting all the form parameters
	vars = CollectHTMLForm("Routed",request)

	# Generate the configuration
 	config=BuildConfigurationJinja2(vars)
	#print type(config)
	
	#Generating random string for the file name
	id_file = id_generator()
	logger.info("Configuration filename is %s.txt" %id_file)

	#print config

	f = open("conf/"+id_file+".txt", 'w+')	
	#for b in config:
	f.write(config)
	f.close()

	#make it HTML compatible. but better to solution is to transform to a table to avoid to display with " |safe" in the jinja template for result. 
	#config = config.replace('\n', '<br>')
	
	tab_config = config.splitlines()
	
	logger.info("Returning the HTML page with the final configuration")

	return render_template("result.html",d=tab_config, file_name=id_file,ssl=request.form['sslfp'])
  
  else:
	name = "Routed Mode"
	return render_template("l3.html",data=name)


###Sniffer mode
@app.route('/sniffer',methods=['GET','POST'])
def S():
  
  if request.method == 'POST':
	
  	logger.info("Sniffer has been selected. let's generate the config")

	vars={}

	#Collecting all the form parameters
	vars = CollectHTMLForm("Sniffer",request)
	
	# Generate configuration
 	config=BuildConfigurationJinja2(vars)

	
	id_file = id_generator()
	logger.info("Configuration filename is %s.txt" %id_file)

	f = open("conf/"+id_file+".txt", 'w+')	
	f.write(config)
	
	f.close()

	#copy config string to a table for jinja2 template.
	tab_config = config.splitlines()
	
	logger.info("Returning the HTML page with the final configuration")
	return render_template("result.html",d=tab_config, file_name=id_file)
  
  else:
	name = "Sniffer Mode"
	return render_template("sniffer.html",data=name)



##SecureWire page
@app.route('/l1',methods=['GET','POST'])
def l1():
  
  if request.method == 'POST':
	
	logger.info("Secure Wire/Transparent has been selected. let's generate the config")

	vars={}
	#Collecting all the form parameters
	vars = CollectHTMLForm("Secure",request)

	# Generate configuration
 	config=BuildConfigurationJinja2(vars)
	
	id_file = id_generator()
	logger.info("Configuration filename is %s.txt" %id_file)

	f = open("conf/"+id_file+".txt", 'w+')	
	f.write(config)
	
	f.close()

	#copy config string to a table for jinja2 template.
	tab_config = config.splitlines()
	
	logger.info("Returning the HTML page with the final configuration")
	return render_template("result.html",d=tab_config, file_name=id_file)
  
  else:
	name = "Secure Wire"
	return render_template("l1.html",data=name)



## main

if __name__ == "__main__":

	#setup logger
  	logger = init_logger()


  	#start app
  	logger.info("Starting Web Interface on port 8080")
	app.run(
           host='0.0.0.0',
           port=8080,
           debug=True)

