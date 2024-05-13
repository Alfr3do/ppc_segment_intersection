from phe import paillier
import numpy as np
import random as rdm
import subprocess
import os
import _thread

import socket
import pickle
import sys
import configparser
from time import sleep

from random import randint
from struct import unpack
from struct import pack
from multiprocessing import Process


config = configparser.ConfigParser()
config.read('bob_config.ini')

local_ip = config['DEFAULT']['LOCAL_IP']
sleep_time = config['DEFAULT']['SLEEP_TIME']


def circuit_bob(index):
    print ("bob " + str(index))    
    os.system("./run_bob -r progs/Logic_singlepair.txt 1111 4 < bob/bob_data_" + str(index) + ".txt > bob/outputbob.txt")



def points_to_equation(x_1,y_1,x_2,y_2):
    
    a = (y_1 - y_2)
    b = (x_2 - x_1)
    c = (x_1*y_2 - x_2*y_1)
    return a,b,c    



def get_d_r(bob_edges, encrypted_param_alice, ha_matrix, r_matrix):

    #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(bob_edges))
    #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(encrypted_param_alice))
    #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(ha_matrix))
    #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" + str(r_matrix))

    num_of_bob_edges = len(bob_edges)
    num_of_alice_edges = len(encrypted_param_alice)

    x_B = [None] * 2
    y_B = [None] * 2
    a_B = [None] * num_of_bob_edges
    b_B = [None] * num_of_bob_edges
    c_B = [None] * num_of_bob_edges

    b_matrix = [None] * num_of_bob_edges
    edge_param_bob = [None] * num_of_bob_edges

    d_r_matrix = [None] * (num_of_bob_edges * num_of_alice_edges)

    for i in range(0, num_of_bob_edges):

        # two points' coordilates of the edge vertices
        x_B[0] = bob_edges[i][0][0]
        y_B[0] = bob_edges[i][0][1]
        x_B[1] = bob_edges[i][1][0]
        y_B[1] = bob_edges[i][1][1]

        a_B[i], b_B[i], c_B[i] = points_to_equation(x_B[0], y_B[0], x_B[1], y_B[1])
        parameters = [a_B[i], b_B[i], c_B[i]] # equation parameter of this line
        #print("parameter: " + str(parameters))
        edge_param_bob[i] = [a_B[i], b_B[i], c_B[i]]

        b_1 = [x_B[0], y_B[0], 1]
        b_2 = [x_B[1], y_B[1], 1]

        b_matrix[i] = [b_1, b_2]

    m = 0  # matrix row number (starts from 0)
    for i in range(0, num_of_alice_edges):
        for j in range(0, num_of_bob_edges):
            d1_d2 = np.dot(encrypted_param_alice[i], np.array(b_matrix[j]).transpose())
            d3_d4 = np.dot(edge_param_bob[j], np.array(ha_matrix[i]).transpose())

            d1 = d1_d2[0]
            d2 = d1_d2[1]
            d3 = d3_d4[0]
            d4 = d3_d4[1]

            d_r_1 = d1 + r_matrix[m][0]
            d_r_2 = d2 + r_matrix[m][1]
            d_r_3 = d3 + r_matrix[m][2]
            d_r_4 = d4 + r_matrix[m][3]

            d_r_matrix[m] = [d_r_1, d_r_2, d_r_3, d_r_4]
            #print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ d_r_matrix[m]: " + str(d_r_matrix[m]))
            m += 1                      

    return d_r_matrix


def get_r(r_length):

    r = [None] * r_length

    for i in range(0, r_length):

        r_1 = rdm.randint(0, 20)
        r_2 = rdm.randint(0, 20)
        r_3 = rdm.randint(0, 20)
        r_4 = rdm.randint(0, 20)

        r[i] =  [r_1, r_2, r_3, r_4] # r is a matrix

    return r


def intersection_decision(bob_edges):
    
    try:
        #get encrypted_param, ha_array from Alice:
        bs = connection.recv(8)
        (length,) = unpack('>Q', bs)
        data = b''
        while len(data) < length:
            to_read = length - len(data)
            data += connection.recv(4096 if to_read > 4096 else to_read)

        # send our 0 ack
        assert len(b'\00') == 1
        connection.sendall(b'\00')

        #encrypted line equition parameters from Alice
        encrypted_param_alice = pickle.loads(data)
        #print('received {!r}'.format(encrypted_param_alice))

        bs = connection.recv(8)
        (length,) = unpack('>Q', bs)
        data = b''
        while len(data) < length:
            to_read = length - len(data)
            data += connection.recv(4096 if to_read > 4096 else to_read)
        #data_ha_matrix = connection.recv(409600000)
        ha_matrix = pickle.loads(data)
        #print('received {!r}'.format(ha_matrix))

        # send our 0 ack
        assert len(b'\00') == 1
        connection.sendall(b'\00')

        num_of_alice_edges = len(encrypted_param_alice)
        r_matrix = get_r(num_of_alice_edges * len(bob_edges)) # every line is an R

        # send d_r_1 ... d_r_4 (matrix) to Alice:
        d_r_matrix = get_d_r(bob_edges, encrypted_param_alice, ha_matrix, r_matrix)
        data_d_r_matrix = pickle.dumps(d_r_matrix)
        length = pack('>Q', len(data_d_r_matrix))
        connection.sendall(length)
        connection.sendall(data_d_r_matrix)

        ack = connection.recv(1)
        #print("@@@@@@@@@@@@@@@@@@@@@@@@" + str(ack))

        for i in range(0, (num_of_alice_edges * len(bob_edges))):
            f = open("./bob/bob_data_" + str(i) + ".txt", "w+")
            f.write(str(r_matrix[i][0]) + "\n" + str(r_matrix[i][1]) + "\n" + str(r_matrix[i][2]) + "\n" + str(r_matrix[i][3]) + "\n")
            f.close()

        # circuit invoke goes here:
        for m in range(0, (num_of_alice_edges * len(bob_edges))):

            # launch circuit
            p = Process(target=circuit_bob, args=([m]))
            p.start()

            sleep(int(sleep_time))
            
            # send the circuit launch confirmation to Alice
            message = b'Circuit launched by Bob'
            print('sending ')#.format(message))
            connection.sendall(message)

            # receive the circuit launch confirmation from Alice
            data_message = connection.recv(10240)
            print('Alice started the circuit ')#.format(data_message))

        #data_message = connection.recv(10240)
        print('Done!')

        # remove all the intermediate input files
        #for n in range(0, (num_of_alice_edges * len(bob_edges))):
            #os.remove("./bob/bob_data_" + str(n) + ".txt")

    finally:
        print()

    f = open("./bob/outputbob.txt", "r")
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

#---------------------------------------------------

# stars here:
if __name__ == '__main__':

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (local_ip, 9999)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    # Wait for a connection
    print('waiting for Alice')
    connection, client_address = sock.accept()
    print('connection from', client_address)

    # edge information of Bob
    
    vertex_matrix_1 = [(1,1), (1,5)] #[[x_1, y_1], [x_2, y_2]]
    vertex_matrix_2 = [(1,5), (4,5)]
    vertex_matrix_3 = [(4,5), (4,4)]
    vertex_matrix_4 = [(4,0), (6,0)]


    bob_edges = [vertex_matrix_1 ]#, vertex_matrix_2, vertex_matrix_3, vertex_matrix_4]
    edge_index = 0
    result = intersection_decision(bob_edges)
    print("Intersection?: " + str(result))

    connection.close()
