# Printshop

This is a straight forward Format String Bug, Needed a refresher from the [fsb playground](https://github.com/Caesurus/how2fsb/blob/master/playground/tutorial_example.py).

Used the FSB to overwrite the lowest bytes of an exit thunk in the Global Offset Table and then exit to trigger the `win()` function. 

[Full Exploit](./expolit.py)

