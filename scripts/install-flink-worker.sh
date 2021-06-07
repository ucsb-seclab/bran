# $1 = public IP of the master node
# S2 = amount of heap (in MB) of the master node
# S3 = amount of heap (in MB) of the worker node
# $4 = number of CPUs for each worker
# $5 = public ssh key of the master node
echo 'LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' | sudo tee --append /etc/environment
sudo apt-get update
sudo apt-get install -y openjdk-8-jre
sudo apt-get install -y openjdk-8-jdk
sudo apt-get install indent
sudo apt-get install unifdef
sudo apt-get install pmccabe
source /etc/environment
wget https://archive.apache.org/dist/flink/flink-1.6.0/flink-1.6.0-bin-scala_2.11.tgz
tar xvzf flink-1.6.0-bin-scala_2.11.tgz
rm flink-1.6.0-bin-scala_2.11.tgz
cd /home/ubuntu/flink-1.6.0/conf
sed -i "s/jobmanager.rpc.address: localhost/jobmanager.rpc.address: $1/g" flink-conf.yaml
sed -i "s/jobmanager.heap.size: 1024m/jobmanager.heap.size: $2m/g" flink-conf.yaml
sed -i "s/taskmanager.heap.size: 1024m/taskmanager.heap.size: $3m/g" flink-conf.yaml
sed -i "s/taskmanager.numberOfTaskSlots: 1/taskmanager.numberOfTaskSlots: $4/g" flink-conf.yaml
echo "$5" >> ~/.ssh/authorized_keys
cd

git clone https://github.com/torvalds/linux
cp -r linux linux0
cp -r linux linux1
cp -r linux linux2
cp -r linux linux3

wget https://neo4j.com/artifact.php?name=neo4j-community-3.2.12-unix.tar.gz
mv artifact.php?name=neo4j-community-3.2.12-unix.tar.gz neo4j.tar.gz
tar xvzf neo4j.tar.gz
rm neo4j.tar.gz
mv neo4j-community-3.2.12 neo4j-community-3.2.12_vuln

sed -i "s/#dbms.active_database=graph.db/dbms.active_database=joernIndex/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.security.auth_enabled=false/dbms.security.auth_enabled=false/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.allow_format_migration=true/dbms.allow_format_migration=true/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.connector.bolt.enabled=true/dbms.connector.bolt.enabled=true/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.connector.http.listen_address=:7474/dbms.connector.http.listen_address=:7475/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.connector.https.listen_address=:7473/dbms.connector.https.listen_address=:7472/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf
sed -i "s/#dbms.connector.bolt.listen_address=:7687/dbms.connector.bolt.listen_address=:7688/g" /home/ubuntu/neo4j-community-3.2.12_vuln/conf/neo4j.conf

mkdir results
mkdir results/word2vec-corpus