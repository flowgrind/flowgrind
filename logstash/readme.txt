Using logstash, elasticsearch, kibana (ELK) to analyze flowgrind logfiles
-------------------------------------------------------------------------

Have a running ELK stack, then

you can use the flowgrind.conf in this directory to import flowgrind logs
into ELK. Logfiles will be index under the flowgrind- index.

Just start flowgrind to show/write all fields using and use numeric values
else the csv parsing will fail, i.e.:

flowgrind -w -p -c interval,through,transac,blocks,iat,rtt,kernel,delay,kernel

Keep in mind that not all fields will contains meaningful data depending on the
additional options you use. Also dont forget to use e.g. direction:S as Kibana
filter if you so desire.

If you run multiple measurements using e.g. path:/tmp/flowgrind-1.log as
filter is useful to only show data of one measurement. If you want to
visualize multiple measurements, e.g. using the average, leave this out. 
