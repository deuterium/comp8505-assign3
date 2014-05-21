COMP 8505 Assignment 3
===
Summer 2014 - chriswood.ca@gmail.com

Objective
---
  - To design a basic DNS spoofing application using any language of your choice.

Mission
---
You have been provided with a detailed module on the DNS protocol, together with basic design and framework for basic DNS traffic manipulation. 
 
For this assignment you are required to implement a DNS spoofing application. This is primarily a POC application. All that is required as acceptable functionality is website spoofing. 

Constraints
---
  - application will simply sense an HTML DNS Query and respond with a crafted Response answer, which will direct the target system to a your own web site
  - Will test this POC on a LAN **on your own systems only**. This means that you are not to carry out any DNS spoofing activity on unsuspecting client systems
  - Required to handle any arbitrary domain name string and craft a spoofed Response
