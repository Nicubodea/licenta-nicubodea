import socket
import struct
import threading
import traceback
import tensorflow

graph = tensorflow.get_default_graph()

def new_connection(s, sock_int, model):
    with graph.as_default():
        while True:
            try:
                q = s.recv(4)
                nr = struct.unpack("I", q)[0]
                print("received", nr)
                q = s.recv(4)
                pid = struct.unpack("I", q)[0]
                print("pid", pid)
                lst = []
                for i in range(nr):
                    q = s.recv(4)
                    lst.append(struct.unpack("I", q)[0])

                print("received", lst)
                todo = numpy.array([lst])
                todo = sequence.pad_sequences(todo, maxlen=500)
                pred = model.predict(todo, 4, 1)

                print("our prediction is", pred)
                if pred[0][0] > 0.5:

                    s.send(struct.pack("I", 1))
                    sock_int.send(bytes(str(pid), 'utf-8'))
                else:
                    s.send(struct.pack("I", 0))
            except Exception as e:
                traceback.print_exc()
                s.close()
                break

def wait_for_input():

    model = reload_model()


    server_address = ('127.0.0.1', 50055)
    sock_int = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_int.connect(server_address)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 50050))
    sock.listen(5)
    while True:
        s, addr = sock.accept()
        print("connection was made")

        t = threading.Thread(target = new_connection, args = (s, sock_int, model))
        t.start()

import numpy
from keras.models import Sequential
from keras.layers import Dense
from keras.layers import LSTM
from keras.layers.embeddings import Embedding
from keras.preprocessing import sequence

def read_data():
    my_read_x = []
    my_read_y = []

    my_read_x2 = []
    my_read_y2 = []
    my_dict = dict()

    q = open("hooks.txt")

    lines = q.readlines()

    q.close()
    for line in lines:
        i0 = line.split(" ")[0].strip()
        i1 = line.split(" ")[1].strip()
        my_dict[i0] = i1


    f = open("CSDMC_API_Train.csv", "r")
    maxlen = 0
    lines = f.readlines()
    for line in lines:
        r = line.split(",")[0].strip()
        c = []

        others = line.split(",")[1].split(" ")
        maxlen = max(maxlen, len(others))
        for t in others:
            try:
                c.append(my_dict[t.strip()])
            except:
                pass
        my_read_x.append(c)
        my_read_y.append(int(r))

    f.close()
    f = open("CSDMC_API_TestData.csv", "r")

    lines = f.readlines()
    for line in lines:
        r = line.split(",")[0].strip()
        c = []
        others = line.split(",")[1].split(" ")
        maxlen = max(maxlen, len(others))
        for t in others:
            try:
                c.append(my_dict[t.strip()])
            except:
                pass
        my_read_x2.append(c)
        my_read_y2.append(int(r))

    return (numpy.array(my_read_x), numpy.array(my_read_y)), (numpy.array(my_read_x2), numpy.array(my_read_y2)), maxlen

from keras.models import model_from_json

def train():
    numpy.random.seed(7)
    (X_train, y_train), (X_test, y_test), maxlen = read_data()
    print('maxlen = ', maxlen)
    max_review_length = 500
    X_train = sequence.pad_sequences(X_train, maxlen=max_review_length)
    X_test = sequence.pad_sequences(X_test, maxlen=max_review_length)
    embedding_vecor_length = 32
    model = Sequential()
    model.add(Embedding(129, embedding_vecor_length, input_length=max_review_length))
    model.add(LSTM(200))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(loss='poisson', optimizer='adam', metrics=['accuracy'])
    print(model.summary())
    model.fit(X_train, y_train, nb_epoch=10, batch_size=32)

    scores = model.evaluate(X_test, y_test, verbose=0)
    print(scores)
    print("Accuracy: %.2f%%" % (scores[1]*100))

    # serialize model to JSON
    model_json = model.to_json()
    with open("model.json", "w") as json_file:
        json_file.write(model_json)
    # serialize weights to HDF5
    model.save_weights("model.h5")
    print("Saved model to disk")

def reload_model():
    # load json and create model
    json_file = open('C:\\Users\\nbodea\\Documents\\Training\\Git\\avxcnn\\model.json', 'r')
    loaded_model_json = json_file.read()
    json_file.close()
    loaded_model = model_from_json(loaded_model_json)
    # load weights into new model
    loaded_model.load_weights("C:\\Users\\nbodea\\Documents\\Training\\Git\\avxcnn\\model.h5")
    print("Loaded model from disk")

    # evaluate loaded model on test data
    loaded_model.compile(loss='poisson', optimizer='adam', metrics=['accuracy'])

    loaded_model._make_predict_function()
    return loaded_model

    #(X_train, y_train), (X_test, y_test), maxlen = read_data()
    X_test = numpy.array([[54, 53, 53, 54, 54, 53, 53, 54, 54, 53, 53, 54, 54, 54, 53, 53, 53, 54, 54, 54, 53, 53, 53, 53, 36, 36, 36, 59, 59, 42]])
    max_review_length = 500
    X_test = sequence.pad_sequences(X_test, maxlen=max_review_length)
    pred = loaded_model.predict(X_test, 4, 1)
    print(pred)
    p = 0
    cnt = 0
    cnt_tot = 0
    #for t in pred:
        #print(y_test[p])
        #if y_test[p] == 1 and t[0] < 0.5:
        #    cnt +=1
        #    cnt_tot += 1
        #elif y_test[p] == 1:
        #    cnt_tot += 1
        #p=p+1
   # print("Detection rate: ", 100.0 - cnt/cnt_tot*100.0)
    #score = loaded_model.evaluate(X_test, y_test, verbose=0)
    #print("%s: %.2f%%" % (loaded_model.metrics_names[1], score[1] * 100))

#train()
#model = reload_model()
#X_test = numpy.array([[54, 53, 53, 54, 54, 53, 53, 54, 54, 53, 53, 54, 54, 54, 53, 53, 53, 54, 54, 54, 53, 53, 53, 53, 36, 36, 36, 59, 59, 42]])
#max_review_length = 500
#X_test = sequence.pad_sequences(X_test, maxlen=max_review_length)
#pred = model.predict(X_test, 4, 1)
#print(pred)
wait_for_input()