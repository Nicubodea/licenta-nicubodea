import subprocess
import os
import sys

dmp = "avx.dmp"
f = open("CSDMC_API_Train.csv", "r");

dicti = []

lines = f.readlines()
for line in lines:
    q = line.split(",")[1]
    funcs = q.split(" ")
    for fun in funcs:
        if fun not in dicti:
            dicti.append(fun)
l = []
ql = []
for k in dicti:
    if k.strip() != "":
        l.append(k)
for t in l:
    ql.append("u kernel32!" + t)
    ql.append("u kernelbase!" + t)
    ql.append("u ntdll!" + t)
txt = "windbg.txt"

f.close()

f = open(txt, "w")

for t in ql:
    f.write(t+"\n")

f.write("q")

f.close()

#e = subprocess.call(["windbg", "-logo", "output.txt", "/z", dmp, "-c", "$<windbg.txt"])
    
#if e != 0:
#    print("[ERROR] windbg failed.")
#    sys.exit(0)
    
f = open("output.txt")
lines = f.readlines()
f.close()

fKernel32 = []
fKernelbase = []
fNtdll = []
fNotInAny = []

i = 0
for line in lines:
    line = line.strip()
    if "u " in line:
        mod = line.split(" ")[2].split("!")[0].strip()
        fun = line.split(" ")[2].split("!")[1].strip()
        if "Couldn't" not in lines[i+1] and "jmp" not in lines[i+2] and "jmp" not in lines[i+3]  and "jmp" not in lines[i+4] and "ret" not in lines[i+2] and "ret" not in lines[i+3] and "ret" not in lines[i+4]:
            mod2 = lines[i+1].split("!")[0].strip().strip(":")
            fun2 = lines[i+1].split("!")[1].strip().strip(":")
            if mod2.lower() != mod.lower() or fun2.lower() != fun.lower():
                print(mod, mod2, fun, fun2)
                i += 1
                continue
            if mod == "kernel32":
                fKernel32.append(fun)
            elif mod == "kernelbase":
                fKernelbase.append(fun)
            elif mod == "ntdll":
                fNtdll.append(fun)
    i+=1
                
for fun in l:
    if fun not in fKernel32 and fun not in fKernelbase and fun not in fNtdll:
        fNotInAny.append(fun)
        
print("---------------- Kernel32.dll ------------------")
print(fKernel32)
        
print("---------------- KernelBase.dll ------------------")
print(fKernelbase)

print("---------------- ntdll.dll ------------------")
print(fNtdll)
        
print("---------------- Not hookable ------------------")
print(fNotInAny)

f = open("to_c.c", "w")
f.write("{\n")
cnt = 0
for q in fKernel32:
    f.write("{\""+q+"\", LIB_KERNEL32, "+str(cnt)+" },\n")
    cnt+=1
for q in fKernelbase:
    f.write("{\""+q+"\", LIB_KERNELBASE, "+str(cnt)+" },\n")
    cnt += 1
for q in fNtdll:
    f.write("{\""+q+"\", LIB_NTDLL, "+str(cnt)+" },\n")
    cnt += 1
f.close()
    