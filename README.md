# Network Security Course

Hello, my name is Segev Burstein and this page represents the fundamental material in which I've studied in this course. 

![Contributors 2](https://img.shields.io/badge/Contributors-2-brightgreen.svg)

# Course Syllabus

**NOTE:** Not every topic mentioned here got a homework assignment due to the fact that we had to work on the project of the course at some stage.

 - DHCP  (Starvation + Persistent)   [Targil 1]
 - ARP   (Spoofing & Detection)      [Targil 2-3]
 - DNS   (Cache Poisoning)           [Targil 4]
 - DNSSEC
 - SSL/TLS, HTTPS
 - IPSec (Transport & Tunneling)
 - TTPs & Kerberos
 - MANET (Mobile Ad-Hoc Network)

# Final Project

As a final project, my partner, **Yakir Demri**, and I took the idea to implement the Onion Routing model, explain it (how it came about and how it relates to the Tor project we know today) and implement it on Python.

## Run on your own
In this section, I'll explain how to operate the system on you on:
 - In order to initialize the routers on the system, the default amount (Which we illustrated in the project demonstration) is only 3 onion router. Each router is stand-alone virtual machine which runs the routers' script. of-course, It's possible to add more as much as you want but an Initialization is required.
 - In case you want to add **more routers**, follow those steps:
 
1.1. Open new router machine (Using VMware\VirtualBox or different PC).

1.2. Go to the 'Onion_Initialization.py' and uncomment the main section.

1.3. Run this script on **linux** [This part creates an SSL certificate (X.509) and generate new set of public & private keys]

1.3.1. On **Windows**, in order to generate self-signed x509 Certificate, use **openssl**. Great tutorial for download located in this website:
https://www.claudiobernasconi.ch/2016/04/17/creating-a-self-signed-x509-certificate-using-openssl-on-windows/

1.4. Close this file (It's recommended to comment this section again in order to avoid situation in which you run that script again) 

1.5. On your directory you'll see a new file called 'directory_server.txt', now, copy his content and paste it in every machine in the system [This file illustrate the directory units which we could not implemented due to the lack of time].

1.6. Validate that all the other machines has identical file content there.

1.6.1. Whenever you inserting more routers (on every machine) go to the 'onion_router.py' and choose unique indentifier for each and every router in your Onion's network: 


`identifier = 1` <-- Change this number!

`PORT = 9000 + identifier`

1.7. You're good to go!

 - In order to run the routers' script, and make them start listening, write this command:
 
On Linux: `$ sudo python3 onion_router.py`

![onion setup](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/router2setup.png)

On Windows `C:\Users\YourPC> python onion_router.py`

After running the routers' script you can continue to the client part

 - In order to run the client's script and start the simulation, write this command:
 
 On Linux: `$ sudo python3 onion_client.py`
 
 ![client setup](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/ClientSetup.png)
 
 On Windows `C:\Users\YourPC> python onion_client.py`
 
 After completing those steps, you're ready to start!
 ## Run on your own
It's important to remember - Our system shows a capability that we have been able to fulfill, therefore there is no special interface with the user here. Despite this, we have created colorful outputs that make it possible to follow what is happening and make it possible to illustrate a little about the interactivity that the system is able to provide in sophisticated situations such as the implementation of Tor provides us.

In order to understand more about the configuration of our implementation, you can take a look at the following image that illustrates the outputs that the machine takes out and the process that goes through from the beginning of the run to the end.

![Image of the procedure](https://github.com/Segev608/NetworkSecurityLab/blob/master/procedure.png)
## Simulation
after starting the scripts at the client & routers let's continue to the next part.
* Client uses the file 'directory_server.txt' to chose 3 routers in a random order (in our case 4, 2, 3):
![Shuffle completed](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/SuffleComplete.png)

* Now, the client is ready to build-up the circuit with the first router - No.4:
![1/3 circuit completed](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/CreateCreated1.png)

* Now, the client is ready to build-up the circuit with the second router - No.2:
![2/3 circuit completed](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/CreateCreated2.png)

* Now, the client is ready to build-up the circuit with the third router - No.3:
![3/3 circuit completed](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/CreateCreated3.png)

**Remember** - the client is located in the most right screen. To his left, located the 'Guard Onion Router' and after that, just standard relay and to his left we can see the 'Exit Onion Router' which passes the traffic from the source - the client, toward the destination.

* Now, after we finished to build-up the circuit, we can initiate the first handshake (In real scenario, this part, as the graph above shows, really initiate a TCP handshake with the website that the client wants to talk with, but we used this part to show full connection - send traffic from client and see that it reached the Exit router) see by yourself that both the Gurad & middle realy **does not** know what is going on inside the packet because it's encrypted with 3 layers of symmetric key encryption:
![Begin connection](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/BeginConnected.png)

* So, the circuit is fully-ready to transfer some real data from the internet, let's request an image from the Tor project website and see it sends back to the client:
![Begin connection](https://github.com/Segev608/NetworkSecurityLab/blob/master/SimulationImg/Data.png)

Finally, as you can see, in the lower-right part of the client's screen, a photo suddenly appeared, this is the photo which we just requested! 
