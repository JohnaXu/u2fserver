def find_start_imooc(fname):
    f = open(fname)

    for line in f:
        if line.startswith('imooc'):
            print line

#find_start_imooc('imooc.txt')
def find_in_imooc(fname):
    f = open(fname)
    for line in f:
        if line.startswith('imooc') and line[:-1].endswith('imooc'):          
             print line

find_in_imooc('imooc.txt')

