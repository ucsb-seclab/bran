# $1 = public IP of the master node
# S2 = amount of heap (in MB) of the master node
# S3 = amount of heap (in MB) of the worker node
# $4 = number of CPUs for each worker
# S5 = list (separated by ':') of private IPs of the worker nodes
echo 'LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' | sudo tee --append /etc/environment
sudo apt-get update
sudo apt-get install pmccabe
sudo apt-get install indent
sudo apt-get install -y openjdk-8-jre
sudo apt-get install -y openjdk-8-jdk
sudo apt-get install -y maven
sudo apt-get install -y unifdef
source /etc/environment
wget https://archive.apache.org/dist/flink/flink-1.6.0/flink-1.6.0-bin-scala_2.11.tgz
tar xvzf flink-1.6.0-bin-scala_2.11.tgz
rm flink-1.6.0-bin-scala_2.11.tgz
cd /home/ubuntu/flink-1.6.0/conf
sed -i "s/jobmanager.rpc.address: localhost/jobmanager.rpc.address: $1/g" flink-conf.yaml
sed -i "s/jobmanager.heap.size: 1024m/jobmanager.heap.size: $2m/g" flink-conf.yaml
sed -i "s/taskmanager.heap.size: 1024m/taskmanager.heap.size: $3m/g" flink-conf.yaml
sed -i "s/taskmanager.numberOfTaskSlots: 1/taskmanager.numberOfTaskSlots: $4/g" flink-conf.yaml
rm slaves
touch slaves
export IFS=":"
for ip in $5; do
  echo "$ip" >> slaves
done
cd

wget https://neo4j.com/artifact.php?name=neo4j-community-3.2.12-unix.tar.gz
mv artifact.php?name=neo4j-community-3.2.12-unix.tar.gz neo4j.tar.gz
tar xvzf neo4j.tar.gz
rm neo4j.tar.gz
sed -i "s/#dbms.active_database=graph.db/dbms.active_database=joernIndex/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.security.auth_enabled=false/dbms.security.auth_enabled=false/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.allow_format_migration=true/dbms.allow_format_migration=true/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.connector.bolt.enabled=true/dbms.connector.bolt.enabled=true/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.connectors.default_listen_address=0.0.0.0/dbms.connectors.default_listen_address=0.0.0.0/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.connectors.default_advertised_address=localhost/dbms.connectors.default_advertised_address=$1/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.connector.http.listen_address=:7474/dbms.connector.http.listen_address=0.0.0.0:7474/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf
sed -i "s/#dbms.connector.https.listen_address=:7473/dbms.connector.https.listen_address=0.0.0.0:7473/g" /home/ubuntu/neo4j-community-3.2.12/conf/neo4j.conf


#dbms.connectors.default_advertised_address=localhost
git clone https://github.com/torvalds/linux

git clone https://git.seclab.cs.ucsb.edu/warmik/kerneline
cd kerneline/lib
mvn install:install-file -Dfile=joern.jar -DgroupId=com.tunnelvisionlabs -DartifactId=joern  -Dversion=0.3.1 -Dpackaging=jar -DgeneratePom=true
mvn install:install-file -Dfile=funcdiff.jar -DgroupId=com.machiry -DartifactId=funcdiff  -Dversion=1.0.0 -Dpackaging=jar -DgeneratePom=true
cd ..
mvn clean package
mkdir kerneline/nvd

mkdir results
mkdir results/word2vec-corpus
ssh-keygen