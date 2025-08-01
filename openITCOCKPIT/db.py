#!/usr/bin/env python3 

'''
Basic Usage
python3 db.py --create
python3 db.py --insert --location test --content donkey
python3 db.py --getLocations
python3 db.py --get --location test
'''
import sqlite3
import argparse
import os
from typing import Tuple
import sys
import traceback

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)
        traceback.print_exc()
    return conn

def create_db(conn):
    createContentTable="""CREATE TABLE IF NOT EXISTS content (
            id integer PRIMARY KEY,
            url text NOT NULL,
            html blob NOT NULL);"""
    createCookieTable="""CREATE TABLE IF NOT EXISTS cookies (
            id integer PRIMARY KEY,
            name text NOT NULL,
            value text NOT NULL);"""
    createCredentialTable="""CREATE TABLE IF NOT EXISTS credentials (
            id integer PRIMARY KEY,
            usr text NOT NULL,
            pwd text NOT NULL);"""
    try:
        c = conn.cursor()
        c.execute(createContentTable)
        c.execute(createCookieTable)
        c.execute(createCredentialTable)
    except Exception as e:
        print(e)
        traceback.print_exc()
def insert(conn, table, data):
    c = conn.cursor()
    sql = F'''INSERT INTO {table}'''
    if table == 'content':
        sql += '(url,html) values(?,?);'
        c.execute(sql, data)
    elif table == 'cookies':
        sql += '(name,value) values(?,?);'
        c.execute(sql, data)
    elif table == 'credentials':
        sql += '(usr,pwd) values(?,?);'
        c.execute(sql, data)
    return c.lastrowid
def get_all(conn, table):
    c = conn.cursor()
    sql=F'''SELECT * FROM {table};'''
    c.execute(sql)
    rows = c.fetchall()
    return rows
def get(conn, table, col, col_cond, value):
    c = conn.cursor()
    sql=F'''SELECT {col} FROM {table} WHERE {col_cond} = '{value}';'''
    c.execute(sql)
    rows = c.fetchall()
    return rows
def get_unique(conn, table, col):
    c = conn.cursor()
    sql = F'SELECT DISTINCT {col} FROM {table}'
    c.execute(sql)
    rows = c.fetchall()
    return rows
if __name__ == "__main__":
    database = r"sqlite.db"
    parser = argparse.ArgumentParser()
    parser.add_argument('--create','-c', help='Create Database File', action='store_true')
    parser.add_argument('--delete','-d', help='Remove Database File', action='store_true')
    subparsers = parser.add_subparsers(dest="subparser")
    # insert options
    insert_parser = subparsers.add_parser('insert', help='Insert captured html content, cookies, or credentials into the database')
    insert_group = insert_parser.add_mutually_exclusive_group(required=True)
    insert_group.add_argument('--content', help='Insert HTML content', action='store_true')
    insert_group.add_argument('--cookie', help='Insert cookies', action="store_true")
    insert_group.add_argument('--credentials', help='Insert credentials', action='store_true')
    # for content table
    insert_parser.add_argument('--url')
    insert_parser.add_argument('--html')
    # for cookie table
    insert_parser.add_argument('--name')
    insert_parser.add_argument('--value')
    # for credentials table
    insert_parser.add_argument('--usr','-u')
    insert_parser.add_argument('--pwd','-p')
    # get options
    get_parser = subparsers.add_parser('get', help='Get captured html content, cookies, or credentials from the database')
    get_group = get_parser.add_mutually_exclusive_group(required=True)
    get_group.add_argument('--content', help='Get HTML content', action='store_true')
    get_group.add_argument('--cookies', help='Get cookies', action="store_true")
    get_group.add_argument('--credentials', help='Get credentials', action='store_true')
    # for content table
    get_parser.add_argument('--url')
    get_parser.add_argument('--html')
    get_parser.add_argument('--urls', action='store_true')
    # for cookies table
    get_parser.add_argument('--name')
    # for credentials table
    get_parser.add_argument('--usr','-u')
    
    get_parser.add_argument('--all', action='store_true')
    if (len(sys.argv) == 1):
       parser.print_help()
       exit()
    args = parser.parse_args(sys.argv[1:])
    conn = create_connection(database)
    if(args.create):
        print("[+] Creating Database")
        create_db(conn)
        exit()
    if(args.delete):
        print(F"[+] Remove database file {database}")
        os.remove(database)
        exit()
    elif(args.subparser == 'insert'):
        if(args.content):
            if(args.url == None or args.html == None):
                parser.error("insert --content requires --url, --html")
            insert(conn,'content', (args.url, args.html))
        if(args.cookie):
            if(args.name == None or args.value == None):
                parser.error("insert --cookie requires --name, --value")
            insert(conn,'cookies', (args.name, args.value))
        if(args.credentials):
            if(args.usr == None or args.pwd == None):
                parser.error("insert --content requires --usr, --pwd")
            insert(conn,'credentials', (args.usr, args.pwd))
        conn.commit()
        print("[+] OK.")
        exit()
    elif(args.subparser == 'get'):
        if(args.content):
            if args.all:
                print(get_all(conn,'content'))
            elif args.urls:
                print(get_unique(conn,'content','url'))
            elif(args.url == None and args.all == False):
                parser.error("get --content requires --url.")
            else:
                print(get(conn,'content', 'html','url', args.url))
        if(args.cookies):
            if args.all:
                print(get_all(conn,'cookies'))
            elif(args.name == None and args.all == False):
                parser.error("get --cookies requires --name.")
            else:
                print(get(conn,'cookies', 'value','name', args.name))
        if(args.credentials):
            if args.all:
                print(get_all(conn,'credentials'))
            elif(args.usr == None and args.all == False):
                parser.error("get --credentials requires --usr.")
            else:
                print(get(conn,'credentials', 'pwd','usr', args.usr))
        exit()

