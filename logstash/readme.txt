Using logstash, elasticsearch, kibana (ELK) to analyze flowgrind logfiles
-------------------------------------------------------------------------

Have a running ELK stack, then

you can use the flowgrind.conf in this directory to import flowgrind logs
into ELK. You probably want to edit the path to flowgrind log directory.
Logfiles will be indexed as flowgrind-%{+YYYY.MM.dd}.

Start flowgrind to show/write all fields and use numeric values, else 
the csv parsing will fail. i.e. start flowgrind with the following
parameters:

flowgrind -w -p -c interval,through,transac,blocks,iat,rtt,kernel,delay,kernel

To start logstash you can use the following command line:

/opt/logstash/bin/logstash agent -f flowgrind.conf

The config expects elasticsearch to be running locally.


Some Remarks:

After the first import create a Kibana time based index pattern
[flowgrind-]YYYY.MM.DD
and select it.

Keep in mind that not all fields will contains meaningful data depending 
on the additional options you use (e.g., RTT). Also dont forget to 
use e.g. direction:"S" as Kibana search (filter) if you so desire.

If you run multiple measurements using e.g. path:"/tmp/flowgrind-1.log" as
search is used to only show data of one measurement. If you want to
visualize multiple measurements, e.g. using the average, leave this out. 

A starting point for a visualization woulde be:

Type: Line Chart

Search: direction:"S"

Y axis:
Aggregation: average
Field: throughput

X axis:
Aggregation: Histogram
Field: timestamp_begin
Interval: 1
