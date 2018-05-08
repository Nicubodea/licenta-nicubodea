import random

f = open("CSDMC_API_TestData.csv", "r");
lines_test = f.readlines();
f.close()
f = open("CSDMC_API_Train.csv", "r");
lines_train = f.readlines();
f.close()

f = open("CSDMC_API_TestData.csv", "w");
q = open("CSDMC_API_Train.csv", "w");

to_test_cnt = 0
to_train_cnt = 0

to_test = ""
to_train = ""

total = len(lines_test) + len(lines_train)
current = 0

for line in lines_test:
    ans = line.split(",")[0]
    funcs = line.split(",")[1].split(" ")
    nrbatches = len(funcs)//500
    
    
    for p in range(nrbatches):
        line = str(ans) + ","
        if p != 0:
            funcs = funcs[500:]
        #print("step ", p, " of length ", len(funcs), " from p*500 to ", min(len(funcs), 500)) 
        for t in range(min(len(funcs),500)):
            line = line + funcs[t].strip() + " "
    
        line = line + "\n"
        if random.randint(1,2) == 2:
            if ans == "0" and to_test_cnt == 4:
                to_train += line
            elif ans == "1" and to_test_cnt == 4:
                to_test += line
                to_test_cnt = 0
            elif ans == "0":
                to_test_cnt += 1
                to_test += line
            else:
                to_train += line
        else:
            to_train += line
        
        #if random.randint(1,3) == 3:
        #    f.write(line)
        #else:
        #    q.write(line)
        
    current += 1
    if current % 10 == 0:
        print(current/total * 100.0)

 
for line in lines_train:
    ans = line.split(",")[0]
    funcs = line.split(",")[1].split(" ")
    nrbatches = len(funcs)//500
    
    
    for p in range(nrbatches):
        line = str(ans) + ","
        if p != 0:
            funcs = funcs[500:]
        #print("step ", p, " of length ", len(funcs), " from p*500 to ", min(len(funcs), 500)) 
        for t in range(min(len(funcs),500)):
            line = line + funcs[t].strip() + " "
    
        line = line + "\n"
        if random.randint(1,2) == 2:
            if ans == "0" and to_test_cnt == 4:
                to_train += line
            elif ans == "1" and to_test_cnt == 4:
                to_test += line
                to_test_cnt = 0
            elif ans == "0":
                to_test_cnt += 1
                to_test += line
            else:
                to_train += line
        else:
            to_train += line
    current += 1
    if current % 10 == 0:
        print(current/total * 100.0)

q.write(to_train)
f.write(to_test)