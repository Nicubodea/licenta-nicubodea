f = open("CSDMC_API_Train.csv", "r");

dicti = dict()

lines = f.readlines()
for line in lines:
    q = line.split(",")[1]
    funcs = q.split(" ")
    for fun in funcs:
        try:
            if dicti[fun] == 1:
                pass
        except:
            dicti[fun] = 1

for k in dicti:
    print(k)

