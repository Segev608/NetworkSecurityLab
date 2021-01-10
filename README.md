# Network Security Course

Hello, my name is segev burstein and this page represents the fundamental material in which I've studied in this course. 


# Course Syllabus

**NOTE:** Not every topic mentioned here got a homework assignment due to the fact that we had to work on the project of the course at some stage.

 - DHCP (Starvation + Persistent) [Targil 1]
 - ARP (Spoofing & Detection) [Targil 2-3]
 - DNS (Cache Poisoning) [Targil 4]
 - DNSSEC
 - SSL/TLS, HTTPS
 - IPSec (Transport & Tunneling)
 - Kerberos

# Final Project

As a final project, my partner, **Yakir Demri**, and I took the idea to implement the Onion Routing model, explain it (how it came about and how it relates to the Tor project we know today) and implement it on Python.

## Run on your own
In this section, I'll explain how to operate the system on you on:
 - In order to initialize the routers on the system, the default amount (Which we illustrated in the project demonstration) is only 3 onion router. Each router is stand-alone virtual machine which runs the routers' script. of-course, It's possible to add more as much as you want but an Initialization is required.
 - In case you want to add **more routers**, follow those steps:
1.1. Open new router machine (Using VMware\VirtualBox or different PC).
1.2. Go to the 'Onion_Initialization.py' and uncomment the main section.
1.3. Run this script [This part creates an SSL certificate (X.509) and generate new set of public & private keys)
1.4. Close this file (It's recommended to comment this section again in order to avoid situation in which you run that script again) 
1.5. On your directory you'll see a new file called 'directory_server.txt', now, copy his content and paste it in every machine in the system [This file illustrate the directory units which we could not implemented due to the lack of time].
1.6. Validate that all the other machines has identical file content there.
1.7. You're good to go!

 - In order to run the routers' script, and make them start listening, write this command:
On Linux: `$ sudo python3 onion_router.py`
On Windows `C:\Users\YourPC> python onion_router.py`
After running the routers' script you can continue to the client part

 - In order to run the client's script and start the simulation, write this command:
 On Linux: `$ sudo python3 onion_client.py`
 On Windows `C:\Users\YourPC> python onion_client.py`
 After completing those steps, you're ready to start!
 ## Run on your own
It's important to remember - Our system shows a capability that we have been able to fulfill, therefore there is no special interface with the user here. Despite this, we have created outputs that make it possible to follow what is happening and make it possible to illustrate a little about the interactivity that the system is able to provide in sophisticated situations such as the implementation of Tor provides us.

In order to understand more about the configuration of our implementation, you can take a look at the following image that illustrates the outputs that the machine takes out and the process that goes through from the beginning of the run to the end.
