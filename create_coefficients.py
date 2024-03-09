# gx_array = [
#     [3,0,0,0,0,0,0,0,0,0,0,0,1,-3,0,-3,0,0,3,-3,0,0,0],
#     [0,3,0,0,0,0,0,0,0,0,0,0,0,1,-3,0,-3,0,0,3,-3,0,0],
#     [0,0,0,0,0,0,0,-1,3,0,3,0,0,-3,3,0,0,0,-3,0,0,0,0],
#     [0,0,0,0,0,-1,3,0,3,0,0,-3,3,0,0,0,-3,0,0,0,0,0,0],
#     [-3,0,-3,0,0,3,-3,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,1],
#     [0,0,0,0,0,0,0,0,0,-1,3,0,3,0,0,-3,3,0,0,0,-3,0,0],
#     [0,0,3,-3,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,1,-3,0,-3],
#     [0,0,0,0,0,0,0,0,0,0,0,-1,3,0,3,0,0,-3,3,0,0,0,-3],
#     [0,0,0,0,0,0,1,-3,0,-3,0,0,3,-3,0,0,0,3,0,0,0,0,0],
#     [0,0,0,1,-3,0,-3,0,0,3,-3,0,0,0,3,0,0,0,0,0,0,0,0],
#     [0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0],
#     [-1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3 , 0 , 0 , 0 ,-3 , 0 , 0 , 0],
#     [0,  0,  3,  0,  0,  0,  0,  0,  0,  0 , 0 , 0 , 0 , 0 , 1 ,-3,  0 ,-3,  0,  0 , 3, -3,  0],
#     [3,  0,  0, -3,  3,  0,  0 , 0 ,-3 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0,  0,  0,  0, -1,  3,  0],
#     [0 , 0 , 0 ,-3,  0,  0,  0 , 0 , 0 , 0  ,0 , 0 , 0 , 0 , 0, -1,  3,  0,  3,  0, 0, -3,  3],
#     [-3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0 , 0 ,-3 , 0],
#     [0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0],
#     [0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0 , 0,  0,  0,  0,  0,  0,  0],
#     [0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0 , 0 , 0 , 0,  0,  0,  1, -3 , 0 ,-3 , 0]
# ]

# fx_array = [
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1],
#     [0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0],
#     [-1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0],
#     [0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1 , 1,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0],
#     [0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0],
#     [0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0],
#     [1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1],
#     [0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1],
#     [-1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1],
#     [1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0],
#     [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0],
#     [0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
#     [0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0]
# ]

# print("DAVE")
# print("------------------G(x)------------------")

# for gx in gx_array:
#     print("G(x) =", end=" ")
#     count = 22
#     gx.reverse()
#     for ind in gx:
#         if ind > 0:
#             print("+ " + str(abs(ind)) + "x^" + str(count), end=" ")
#         elif ind < 0:
#             print("- " + str(abs(ind)) + "x^" + str(count), end =" ")
#         count = count - 1
        
#     print("   g(x) * (-1) =", end=" ")
#     count = 22
#     for ind in gx:
#         if ind > 0:
#             print("- " + str(abs(ind)) + "x^" + str(count), end=" ")
#         elif ind < 0:
#             print("+ " + str(abs(ind)) + "x^" + str(count), end =" ")
#         count = count - 1
        
#     print()
    
# print("------------------f(x)------------------")

# for fx in fx_array:
#     print("f(x) =", end=" ")
#     count = 22
#     fx.reverse()
#     for ind in fx:
#         if ind > 0:
#             print("+ " + str(abs(ind)) + "x^" + str(count), end=" ")
#         elif ind < 0:
#             print("- " + str(abs(ind)) + "x^" + str(count), end =" ")
#         count = count - 1
        
#     print("   f(x) * (-1) =", end=" ")
#     count = 22
#     for ind in fx:
#         if ind > 0:
#             print("- " + str(abs(ind)) + "x^" + str(count), end=" ")
#         elif ind < 0:
#             print("+ " + str(abs(ind)) + "x^" + str(count), end =" ")
#         count = count - 1
#     print()
    
 
# Reset fx and gx arrays
gx_array = [
    [3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0],
    [0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0],
    [0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0],
    [0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0],
    [-3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1],
    [0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0],
    [0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3],
    [0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0],
    [0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0],
    [-1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0],
    [0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0],
    [3,  0,  0, -3,  3,  0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0],
    [0,  0,  0, -3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3],
    [-3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  3,  0,  3,  0,  0, -3,  3,  0,  0,  0, -3,  0],
    [0,  0,  0,  0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0],
    [0,  1, -3,  0, -3,  0,  0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  3, -3,  0,  0,  0,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -3,  0, -3,  0]
]

fx_array = [
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1],
    [0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0],
    [-1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0],
    [0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0],
    [0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0],
    [0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0],
    [1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1],
    [0,  0,  0,  0, -1, -1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1],
    [-1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1],
    [1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0],
    [0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1, -1,  0,  0,  0,  0, -1, -1, -1,  0,  0,  0],
    [0,  0,  0,  0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0, -1,  1,  0,  0,  0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0],
    [0,  0,  1,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, -1,  1,  0,  0]
]
    
print("Frank")
print("------------------G(x)------------------")

for gx in gx_array:
    print("G(x) =", end=" ")
    count = 22
    gx.reverse()
    for ind in gx:
        if ind > 0:
            print("+ " + str(abs(ind)) + "x^" + str(count), end=" ")
        elif ind < 0:
            print("- " + str(abs(ind)) + "x^" + str(count), end =" ")
        count = count - 1
        
    print("   g(x) * (-1) =", end=" ")
    count = 22
    for ind in gx:
        if ind > 0:
            print("- " + str(abs(ind)) + "x^" + str(count), end=" ")
        elif ind < 0:
            print("+ " + str(abs(ind)) + "x^" + str(count), end =" ")
        count = count - 1
        
    print()
    
print("------------------f(x)------------------")

for fx in fx_array:
    print("f(x) =", end=" ")
    count = 22
    fx.reverse()
    for ind in fx:
        if ind > 0:
            print("+ " + str(abs(ind)) + "x^" + str(count), end=" ")
        elif ind < 0:
            print("- " + str(abs(ind)) + "x^" + str(count), end =" ")
        count = count - 1
        
    print("   f(x) * (-1) =", end=" ")
    count = 22
    for ind in fx:
        if ind > 0:
            print("- " + str(abs(ind)) + "x^" + str(count), end=" ")
        elif ind < 0:
            print("+ " + str(abs(ind)) + "x^" + str(count), end =" ")
        count = count - 1
    print()