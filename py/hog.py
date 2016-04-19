from multiprocessing import Pool
import time
def f(x):
    # Put any cpu (only) consuming operation here. I have given 1 below -
    while True:
        time.sleep(0.005);
        x * x;
# decide how many cpus you need to load with.
no_of_cpu_to_be_consumed = 400
p = Pool(processes=no_of_cpu_to_be_consumed)
p.map(f, range(no_of_cpu_to_be_consumed)
