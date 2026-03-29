
import sys
content = open(sys.argv[1]).read()
# Replace the current hash 'acc6eba' with 'reword'
new_content = content.replace('pick acc6eba', 'reword acc6eba')
with open(sys.argv[1], 'w') as f2:
    f2.write(new_content)
