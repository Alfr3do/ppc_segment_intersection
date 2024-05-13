from phe import paillier
import numpy as np
import random as r
import subprocess
import os
import _thread
import time
import socket
import pickle
import sys
import configparser
from time import sleep
from random import randint
from struct import unpack
from struct import pack


config = configparser.ConfigParser()
config.read('alice_config.ini')

bob_ip = config['DEFAULT']['BOB_IP']


def circuit_alice(index):
    print ("alice " + str(index))
    os.system("./run_alice -r progs/Logic_singlepair.txt 1112 localhost < alice/alice_data_" + str(index) + ".txt > alice/outputalice.txt")


def points_to_equation(x_1,y_1,x_2,y_2):
    
    a = (y_1 - y_2)
    b = (x_2 - x_1)
    c = (x_1*y_2 - x_2*y_1)
    return a,b,c



def compose_data_for_bob(alice_edges, public_key, private_key):

    number_of_edges = len(alice_edges)
    #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(number_of_edges))

    x_A = [None] * 2 # 2 vertices each edge
    y_A = [None] * 2
    # segment ecuation coeficients
    a_A = [None] * number_of_edges
    b_A = [None] * number_of_edges
    c_A = [None] * number_of_edges

    ha_matrix = [None] * number_of_edges
    encrypted_param = [None] * number_of_edges

    for i in range(0, number_of_edges):

        # two points' coordilates of the edge vertices
        x_A[0] = alice_edges[i][0][0]
        y_A[0] = alice_edges[i][0][1]
        x_A[1] = alice_edges[i][1][0]
        y_A[1] = alice_edges[i][1][1]

        a_A[i],b_A[i],c_A[i] = points_to_equation(x_A[0],y_A[0],x_A[1],y_A[1])
        parameters = [a_A[i],b_A[i],c_A[i]] # equation parameter of this line
        print("line coeficients : " + str(parameters))
        encrypted_param[i] = [public_key.encrypt(x) for x in parameters] # encrypt every equation parameter

        #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(encrypted_param[i]))

        a_1 = [x_A[0], y_A[0], 1]
        a_2 = [x_A[1], y_A[1], 1]

        ha_1 = [public_key.encrypt(x) for x in a_1]
        ha_2 = [public_key.encrypt(x) for x in a_2]
        ha_matrix[i] = [ha_1, ha_2]

    return encrypted_param, ha_matrix



def intersection_decision(alice_edges):
    public_key, private_key = paillier.generate_paillier_keypair()
    encrypted_param, ha_matrix = compose_data_for_bob(alice_edges, public_key, private_key)

    
    try:
        # send ha, ha_1, ha_2 to Bob:
        data_encrypted_param = pickle.dumps(encrypted_param) # encrypted_param is a object, use pickle to do the serialization
        length = pack('>Q', len(data_encrypted_param))
        sock.sendall(length)
        #print('sending ')#.format(data_encrypted_param))
        sock.sendall(data_encrypted_param)

        ack = sock.recv(1)
        #print("@@@@@@@@@@@@@@@@@@@@@@@@" + str(ack))


        data_ha_matrix = pickle.dumps(ha_matrix)
        length = pack('>Q', len(data_ha_matrix))
        sock.sendall(length)
        #print('sending ')#.format(data_ha_matrix))
        sock.sendall(data_ha_matrix)

        ack = sock.recv(1)
        #print("@@@@@@@@@@@@@@@@@@@@@@@@" + str(ack))

        # get d_r_1 ... d_r_4 (matrix) from Bob:
        bs = sock.recv(8)
        (length,) = unpack('>Q', bs)
        data = b''
        while len(data) < length:
            to_read = length - len(data)
            data += sock.recv(4096 if to_read > 4096 else to_read)

        #data_d_r_matrix = sock.recv(409600000)
        d_r_matrix = pickle.loads(data)
        print('received ')#.format(d_r_matrix))

        # send our 0 ack
        assert len(b'\00') == 1
        sock.sendall(b'\00')

        for i in range(0, len(d_r_matrix)):
            u_1 = private_key.decrypt(d_r_matrix[i][0])
            u_2 = private_key.decrypt(d_r_matrix[i][1])
            u_3 = private_key.decrypt(d_r_matrix[i][2])
            u_4 = private_key.decrypt(d_r_matrix[i][3])
            f = open("./alice/alice_data_" + str(i) + ".txt", "w+")
            f.write(str(u_1) + "\n" + str(u_2) + "\n" + str(u_3) + "\n" + str(u_4) + "\n")
            f.close()

        # circuit invoke goes here:
        for m in range(0, len(d_r_matrix)):
            print('wating for Bob launch the circuit ...')
            # wait confirmation from Bob (Bob launched the circuit)
            data_message = sock.recv(10240)
            print('received ')#.format(data_message))

            #print("decoded ############# decoded ############ " + data_message.decode())
            #if (data_message.decode() == "1"):
            #   print("result established!!!!!!!!!!!!!!!")
            #    break
            
            circuit_alice(m)

            # sending confirmation to Bob
            message = b'Circuit launched by Alice'
            print('sending ')#.format(message))
            sock.sendall(message)

        # remove all the intermediate input files 
        #for n in range(0, len(d_r_matrix)):
            #os.remove("./alice/alice_data_" + str(n) + ".txt")

    finally:
        print()
    #here the comparison is finished
    f = open("./alice/outputalice.txt", "r")
    contents =f.read()
    f.close()
    print("******************************")
    result = contents[-2:].strip()
    if (result == "1"):
        print("Intersection ")
        print("******************************")
        return True
    else:
        print("No intersection")
        print("******************************")
        return False
    

# stars here:
if __name__ == '__main__':

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (bob_ip, 9999)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    # edge information of Alice
    vertex_matrix_1 = [[0, 4], [3, 2]] #[[x_1, y_1], [x_2, y_2]]
    vertex_matrix_2 = [[3, 1], [5, 1]]
    vertex_matrix_3 = [[5, 1], [6, 3]]
    vertex_matrix_4 = [[6, 3], [2, 3]]


    alice_edges = [ vertex_matrix_1] #, vertex_matrix_2, vertex_matrix_3, vertex_matrix_4]

    result = intersection_decision(alice_edges)
    print("Intersection?: " + str(result))

    sock.close()
