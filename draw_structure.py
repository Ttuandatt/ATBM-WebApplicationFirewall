import os

# Thay đường dẫn này bằng nơi bạn cài Graphviz, ví dụ:
graphviz_path = r"C:\Program Files\Graphviz\bin"
os.environ["PATH"] += os.pathsep + graphviz_path

from diagrams import Diagram, Cluster, Node
from diagrams.aws.network import VPC, PublicSubnet, PrivateSubnet, NATGateway, InternetGateway, ALB
from diagrams.aws.compute import EC2

with Diagram("Dev VPC + ALB + Bastion Stack", show=True):

    igw = InternetGateway("Internet Gateway")

    with Cluster("VPC"):
        vpc = VPC("VPC1")

        # Public Subnets
        pub_sub_az1 = PublicSubnet("PublicSubnetAZ1")
        pub_sub_az2 = PublicSubnet("PublicSubnetAZ2")

        # Private Subnets
        priv_sub_az1 = PrivateSubnet("PrivateSubnetAZ1")
        priv_sub_az2 = PrivateSubnet("PrivateSubnetAZ2")

        # NAT
        nat = NATGateway("NatGatewayAZ1")

        # Security Groups (Node)
        alb_sg = Node("ALB SG")
        bastion_sg = Node("Bastion SG")
        app_sg = Node("App SG")

        # ALB
        alb = ALB("ALB")

        # EC2
        bastion = EC2("Bastion")
        app_instance = EC2("AppInstance")

        # Connections
        igw >> alb
        alb >> app_instance
        bastion >> app_instance
        priv_sub_az1 >> nat >> igw
        priv_sub_az2 >> nat >> igw
