import argparse
import pathlib
import sqlite3


class DbLoader:
    @staticmethod
    def create(db_file: pathlib.Path, libc_db_path: pathlib.Path):
        connection = sqlite3.connect(str(db_file.absolute()))
        cursor = connection.cursor()
        cursor.execute(
            "create table libc("
                "id INTEGER NOT NULL PRIMARY KEY, "
                "name VARCHAR, "
                "data BLOB"
            ");"
        )

        cursor.execute(
            "create table symbol("
                "id INTEGER NOT NULL PRIMARY KEY,"
                "name VARCHAR "
            ");"
        )

        cursor.execute(
            "create table symbol2address("
                "symbol_id INTEGER REFERENCES symbol, "
                "address INTEGER, "
                "libc_id INTEGER REFERENCES libc"
            ");"
        )
        connection.commit()
        files = tuple(x for x in libc_db_path.iterdir() if x.is_file() and x.name.endswith('.symbols'))
        number_of_files = len(files)

        libc_insert = 'insert into libc values (?, ?, ?)'
        symbol2address_insert = 'insert into symbol2address values (?, ?, ?)'
        symbol_insert = 'insert into symbol values (?, ?)'

        symbol_id = 0
        symbols = {}
        for index, file in enumerate(files):
            print(f"{index+1}/{number_of_files} {file.stem}")

            lib_file = file.with_suffix('.so')
            assert lib_file.exists() and lib_file.is_file(), lib_file

            with file.open('r') as infile:
                for line in infile.readlines():
                    line = line.strip()
                    symbol_name, address_hex = line.split()
                    if symbol_name not in symbols:
                        cursor.execute(symbol_insert, (symbol_id, symbol_name))
                        symbols[symbol_name] = symbol_id
                        symbol_id += 1

                    cursor.execute(symbol2address_insert, (symbols[symbol_name], int(address_hex, 16), index))

            with lib_file.open('rb') as infile:
                cursor.execute(libc_insert, (index, file.stem, infile.read()))

        cursor.close()
        connection.commit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('db_file', type=pathlib.Path)
    parser.add_argument('libc_db', type=pathlib.Path)
    args = parser.parse_args()

    DbLoader.create(args.db_file, args.libc_db)
