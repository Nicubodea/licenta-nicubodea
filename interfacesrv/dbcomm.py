import sqlite3
import datetime
import traceback
import threading

class DBHandler:

    class _DBHandler:
        def __init__(self):
            conn = sqlite3.connect("mhvev.db")

            self.glock = threading.Lock()

            try:
                conn.execute('''CREATE TABLE PROCESS_TIMELINE
                                     (ID INTEGER PRIMARY KEY    AUTOINCREMENT,
                                     PROCESSNAME        TEXT,
                                     PROCESSID          INTEGER     NOT NULL,
                                     COMPLETED          INTEGER     NOT NULL,
                                     DATE_STARTED       TIMESTAMP,
                                     DATE_COMPLETED     TIMESTAMP,
                                     SESSION            INT,
                                     STATE              INT
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE ALERT_TIMELINE
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                     ALERT_ID       INTEGER,
                                     EXCEPTED       INTEGER,
                                     SESSION        INT,
                                     TIMELINE_ID    INTEGER
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE PROCESS_TIMELINE_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                     ID_TIMELINE INTEGER NOT NULL,
                                     EVENTTYPE INTEGER,
                                     EVENT_ID INTEGER NOT NULL
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE PROCESS_START_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                    NAME    TEXT,
                                    PID     INTEGER,
                                    CR3     INTEGER,
                                    EPROCESS INTEGER,
                                    PROTECTION INTEGER,
                                     DATE_EVENT TIMESTAMP
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE PROCESS_TERMINATE_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                    NAME    TEXT,
                                    PID     INTEGER,
                                    CR3     INTEGER,
                                    EPROCESS INTEGER,
                                    PROTECTION INTEGER,
                                     DATE_EVENT TIMESTAMP
                                     );''')
            except Exception as e:
                print(e)


            try:
                conn.execute('''CREATE TABLE MODULE_LOAD_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                     NAME       TEXT,
                                     START      INTEGER,
                                     END        INTEGER,
                                     PROCESSNAME TEXT,
                                     PID         TEXT,
                                     PROTECTED   INTEGER,
                                     DATE_EVENT TIMESTAMP
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE MODULE_UNLOAD_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                     NAME       TEXT,
                                     MODSTART      INTEGER,
                                     MODEND        INTEGER,
                                     PROCESSNAME TEXT,
                                     PID         TEXT,
                                     PROTECTED   INTEGER,
                                     DATE_EVENT TIMESTAMP
                                     );''')
            except Exception as e:
                print(e)


            try:
                conn.execute('''CREATE TABLE MODULE_ALERT_EVENT
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                      ATTACKERNAME TEXT,
                                      ATTACKERSTART INTEGER,
                                      ATTACKEREND INTEGER,
                                      VICTIMNAME TEXT,
                                      VICTIMSTART INTEGER,
                                      VICTIMEND INTEGER,
                                      PROCESSNAME TEXT,
                                      PROCESSPID INTEGER,
                                      RIP INTEGER,
                                      ADDRESS INTEGER,
                                      FUNCTIONNAME TEXT,
                                      ACTION INTEGER,
                                      PROTECTION INTEGEER,
                                     DATE_EVENT TIMESTAMP
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE MODULE_ALERT_INSTRUCTION
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                      MNEMONIC INTEGER,
                                      INSTRUX  TEXT,
                                      LENGTH   INTEGER,
                                      ALERT_ID INTEGER
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE PROTECTED_PROCESSES
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                        PROCESSNAME TEXT,
                                        MASK        INTEGER
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE EXCEPTIONS
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                        ALERT_ID INTEGER
                                     );''')
            except Exception as e:
                print(e)

            try:
                conn.execute('''CREATE TABLE BLOCKED_DLLS
                                     (ID INTEGER PRIMARY KEY     AUTOINCREMENT,
                                        DLL_NAME TEXT
                                     );''')
            except Exception as e:
                print(e)

            conn.close()

    instance = None
    def __init__(self):
        if DBHandler.instance is None:
            DBHandler.instance = DBHandler._DBHandler()

    def _timeline_to_dict(self, id, processname, pid, completed, date_started, date_ended, session, state, evts):
        return {
            "id": id,
            "process": processname,
            "pid":  pid,
            "completed": completed,
            "date_started": date_started,
            "date_ended": date_ended,
            "session": session,
            "events": evts,
            "state": state
        }

    def _proc_create_event_to_dict(self, id, name, pid, cr3, eprocess, protection, event_date):

        return {
            "id": id,
            "name": name,
            "pid": pid,
            "cr3": cr3,
            "eprocess": eprocess,
            "protection": protection,
            "event_date": event_date,
            "type": 0
        }

    def _proc_terminate_event_to_dict(self, id, name, pid, cr3, eprocess, protection, event_date):

        return {
            "id": id,
            "name": name,
            "pid": pid,
            "cr3": cr3,
            "eprocess": eprocess,
            "protection": protection,
            "event_date": event_date,
            "type": 1
        }

    def _mod_load_event_to_dict(self, id, name, start, end, procname, pid, protected, date_event):
        return {
            "id": id,
            "name": name,
            "start": start,
            "end": end,
            "process_name": procname,
            "pid": pid,
            "protected": protected,
            "type": 2
        }

    def _mod_unload_event_to_dict(self, id, name, start, end, procname, pid, protected, date_event):
        return {
            "id": id,
            "name": name,
            "start": start,
            "end": end,
            "process_name": procname,
            "pid": pid,
            "protected": protected,
            "type": 3
        }


    def _mod_alert_event_to_dict(self, id, attackername, attackerstart, attackerend, victiname, victimstart, victimend, processname, pid, rip, address, functionname, action, protection, instructions):
        return {
            "id": id,
            "attacker_name": attackername,
            "attacker_start": attackerstart,
            "attacker_end": attackerend,
            "victim_name": victiname,
            "victim_start": victimstart,
            "victim_end": victimend,
            "process_name": processname,
            "pid": pid,
            "rip": rip,
            "address": address,
            "functionname": functionname,
            "action": action,
            "protection": protection,
            "instructions": instructions,
            "type": 4
        }

    def _instruction_to_dict(self, mnemonic, instrux, length):
        return {
            "mnemonic": mnemonic,
            "text": instrux,
            "length": length
        }

    def _alert_timeline_to_dict(self, id, alert, excepted, session, evts):
        return {
            "id": id,
            "alert": alert,
            "excepted": excepted,
            "session": session,
            "timeline_id": evts
        }

    ############################################################################
    ####################                                    ####################
    ####################         PROCESS TIMELINE           ####################
    ####################                                    ####################
    ############################################################################
    def create_new_timeline(self, processname, pid, session, state):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO PROCESS_TIMELINE(PROCESSNAME, PROCESSID, COMPLETED, DATE_STARTED, SESSION, STATE) VALUES (?,?,?,?,?,?)", (processname, pid, 0, datetime.datetime.now(), session, state))
            conn.commit()
            ans = cursor.lastrowid
        except:
            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def update_timeline_state(self, timeline_id, new_state, acquired=False):
        if not acquired:
            DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")

        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE PROCESS_TIMELINE SET STATE = ? WHERE ID = ?",
                           (new_state, timeline_id))
            conn.commit()
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        if not acquired:
            DBHandler.instance.glock.release()

    def get_timeline(self, timeline_id, acquired=False):
        # will also put all of the events in the returned timeline
        if not acquired:
            DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM PROCESS_TIMELINE WHERE ID = ?", (timeline_id,))
            row = cursor.fetchone()
            cursor.execute("SELECT * FROM PROCESS_TIMELINE_EVENT WHERE ID_TIMELINE = ?" , (timeline_id,))
            cursor2 = conn.cursor()
            cursor3 = conn.cursor()
            evts = []
            for current in cursor:
                if int(current[2]) == 0:
                    cursor2.execute("SELECT * FROM PROCESS_START_EVENT WHERE ID = ?", (current[3],))
                    row_1 = cursor2.fetchone()
                    evts.append(self._proc_create_event_to_dict(row_1[0],row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6]))
                elif int(current[2]) == 1:
                    cursor2.execute("SELECT * FROM PROCESS_TERMINATE_EVENT WHERE ID = ?", (current[3],))
                    row_1 = cursor2.fetchone()
                    evts.append(self._proc_terminate_event_to_dict(row_1[0],row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6]))
                elif int(current[2]) == 2:
                    cursor2.execute("SELECT * FROM MODULE_LOAD_EVENT WHERE ID = ?", (current[3],))
                    row_1 = cursor2.fetchone()
                    evts.append(self._mod_load_event_to_dict(row_1[0],row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6], row_1[7]))
                elif int(current[2]) == 3:
                    cursor2.execute("SELECT * FROM MODULE_UNLOAD_EVENT WHERE ID = ?", (current[3],))
                    row_1 = cursor2.fetchone()
                    evts.append(self._mod_unload_event_to_dict(row_1[0],row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6], row_1[7]))
                elif int(current[2]) == 4:
                    cursor2.execute("SELECT * FROM MODULE_ALERT_EVENT WHERE ID = ?", (current[3],))
                    row_1 = cursor2.fetchone()
                    instructions = []
                    cursor3.execute("SELECT * FROM MODULE_ALERT_INSTRUCTION WHERE ALERT_ID = ?", (current[3],))
                    for instrux in cursor3:
                        instructions.append(self._instruction_to_dict(instrux[1], instrux[2], instrux[3]))
                    evts.append(self._mod_alert_event_to_dict(row_1[0], row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6], row_1[7], row_1[8], row_1[9], row_1[10], row_1[11], row_1[12], row_1[13], instructions))

            ans = self._timeline_to_dict(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], evts)
        except:
            print(timeline_id)
            traceback.print_exc()
            conn.rollback()

        conn.close()
        if not acquired:
            DBHandler.instance.glock.release()
        return ans
    def complete_timeline(self, timeline_id):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")

        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE PROCESS_TIMELINE SET COMPLETED = ?, DATE_COMPLETED = ? WHERE ID = ?", (1, datetime.datetime.now(), str(timeline_id)))
            conn.commit()
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()

    def complete_all_timelines(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")

        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE PROCESS_TIMELINE SET COMPLETED = ?, DATE_COMPLETED = ? WHERE COMPLETED = ?",
                           (1, datetime.datetime.now(), 0))
            conn.commit()
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()

    def get_all_timelines_grouped_by_session(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM PROCESS_TIMELINE ORDER BY ID DESC")

            timelines = []

            for row in cursor:
                timelines.append(self._timeline_to_dict(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], None))
            ans = timelines
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    ############################################################################
    ####################                                    ####################
    ####################         ALERT TIMELINE             ####################
    ####################                                    ####################
    ############################################################################

    def create_new_alert_timeline(self, alert_id, session):
        # get all events from timeline_id
        # for every event create a mirroring event in ALERT_EVENTS table
        # get alert
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")

        try:
            cursor = conn.cursor()

            alert = self.get_alert_by_alert_id(alert_id, True)
            current_timeline_id = self.get_timeline_id_for_event(alert["pid"], True)

            cursor.execute("INSERT INTO ALERT_TIMELINE(ALERT_ID, EXCEPTED, SESSION, TIMELINE_ID) VALUES (?, ?, ?, ?)", (alert_id, 0, session, current_timeline_id))

            conn.commit()
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()

    def get_alert_timeline(self, alert_timeline_id):
        # will also put all of the events in the returned timeline
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ALERT_TIMELINE WHERE ID = ?", (alert_timeline_id,))
            row = cursor.fetchone()

            cursor.execute("SELECT * FROM MODULE_ALERT_EVENT WHERE ID = ?", (row[1],))
            row_1 = cursor.fetchone()
            instructions = []
            cursor.execute("SELECT * FROM MODULE_ALERT_INSTRUCTION WHERE ALERT_ID = ?", (row[1],))
            for instrux in cursor:
                instructions.append(self._instruction_to_dict(instrux[1], instrux[2], instrux[3]))
            lastalert = self._mod_alert_event_to_dict(row_1[0], row_1[1], row_1[2], row_1[3], row_1[4], row_1[5],
                                              row_1[6], row_1[7], row_1[8], row_1[9], row_1[10], row_1[11],
                                              row_1[12], row_1[13], instructions)

            ans = self._alert_timeline_to_dict(row[0], lastalert, row[2], row[3], row[4])
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def get_all_alert_timelines_grouped_by_session(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ALERT_TIMELINE ORDER BY ID DESC")

            timelines = []
            for row in cursor:
                alert = self.get_alert_by_alert_id(row[1], acquired=True)
                timelines.append(self._alert_timeline_to_dict(row[0], alert, row[2], row[3], row[4]))
            ans = timelines
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans
    ############################################################################
    ####################                                    ####################
    ####################         UTILS                      ####################
    ####################                                    ####################
    ############################################################################

    def get_current_session(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = 0
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(SESSION) FROM PROCESS_TIMELINE")

            ans = cursor.fetchone()[0]+1

        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def get_timeline_id_for_event(self, pid, acquired = False):
        if not acquired:
            DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM PROCESS_TIMELINE WHERE COMPLETED = ? AND PROCESSID = ?", (0, pid))

            ans = cursor.fetchone()[0]

        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        if not acquired:
            DBHandler.instance.glock.release()
        return ans
    ############################################################################
    ####################                                    ####################
    ####################         EVENTS                     ####################
    ####################                                    ####################
    ############################################################################

    def create_new_process_event(self, name, pid, cr3, eprocess, protection, timeline_id):
        """
        NAME    TEXT,
        PID     INTEGER,
        CR3     INTEGER,
        EPROCESS INTEGER,
        PROTECTION INTEGER,
         DATE_EVENT TIMESTAMP
        :param name:
        :param pid:
        :param cr3:
        :param eprocess:
        :param protection:
        :param timeline_id:
        :return:
        """
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO PROCESS_START_EVENT(`NAME`, PID, CR3, EPROCESS, PROTECTION, DATE_EVENT) VALUES (?,?,?,?,?,?)",
                (name, pid, cr3, eprocess, protection, datetime.datetime.now()))

            last_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO PROCESS_TIMELINE_EVENT (ID_TIMELINE, EVENTTYPE, EVENT_ID) VALUES (?, ?, ?)",
                (timeline_id, 0, last_id)
            )

            conn.commit()
            ans = last_id
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans
    def create_terminate_process_event(self, name, pid, cr3, eprocess, protection, timeline_id):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO PROCESS_TERMINATE_EVENT(`NAME`, PID, CR3, EPROCESS, PROTECTION, DATE_EVENT) VALUES (?,?,?,?,?,?)",
                (name, pid, cr3, eprocess, protection, datetime.datetime.now()))

            last_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO PROCESS_TIMELINE_EVENT (ID_TIMELINE, EVENTTYPE, EVENT_ID) VALUES (?, ?, ?)",
                (timeline_id, 1, last_id)
            )

            conn.commit()
            ans = last_id
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def create_module_load_event(self, name, start, end, procname, pid, protected, timeline_id):
        """
        NAME       TEXT,
                                 START      INTEGER,
                                 END        INTEGER,
                                 PROCESSNAME TEXT,
                                 PID         TEXT,
                                 PROTECTED   INTEGER,
                                 DATE_EVENT TIMESTAMP
        :param name:
        :param start:
        :param end:
        :param procname:
        :param pid:
        :param protected:
        :param timeline_id:
        :return:
        """
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO MODULE_LOAD_EVENT(`NAME`, START, END, PROCESSNAME, PID, PROTECTED, DATE_EVENT) VALUES (?,?,?,?,?,?,?)",
                (name, start, end, procname, pid, protected, datetime.datetime.now()))

            last_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO PROCESS_TIMELINE_EVENT (ID_TIMELINE, EVENTTYPE, EVENT_ID) VALUES (?, ?, ?)",
                (timeline_id, 2, last_id)
            )

            conn.commit()
            ans = last_id
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def create_module_unload_event(self, name, start, end, procname, pid, protected, timeline_id):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO MODULE_UNLOAD_EVENT(`NAME`, START, END, PROCESSNAME, PID, PROTECTED, DATE_EVENT) VALUES (?,?,?,?,?,?,?)",
                (name, start, end, procname, pid, protected, datetime.datetime.now()))

            last_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO PROCESS_TIMELINE_EVENT (ID_TIMELINE, EVENTTYPE, EVENT_ID) VALUES (?, ?, ?)",
                (timeline_id, 3, last_id)
            )

            conn.commit()
            ans = last_id
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def create_module_alert_event(self, attackername, attackerstart, attackerend, victimname, victimstart, victimend, processname, pid, rip, address, functionname, action ,protection, timeline_id):
        """
          ATTACKERNAME TEXT,
          ATTACKERSTART INTEGER,
          ATTACKEREND INTEGER,
          VICTIMNAME TEXT,
          VICTIMSTART INTEGER,
          VICTIMEND INTEGER,
          PROCESSNAME TEXT,
          PROCESSPID INTEGER,
          RIP INTEGER,
          ADDRESS INTEGER,
          FUNCTIONNAME TEXT,
          ACTION INTEGER,
          PROTECTION INTEGEER,
         DATE_EVENT TIMESTAMP
        :param attackername:
        :param attackerstart:
        :param attackerend:
        :param victimname:
        :param victimstart:
        :param victimend:
        :param processname:
        :param pid:
        :param address:
        :param functionname:
        :param action:
        :param protection:
        :param timeline_id:
        :return:
        """
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO MODULE_ALERT_EVENT(ATTACKERNAME, ATTACKERSTART, ATTACKEREND, VICTIMNAME, VICTIMSTART, VICTIMEND, PROCESSNAME, PROCESSPID, RIP, ADDRESS, FUNCTIONNAME, ACTION, PROTECTION, DATE_EVENT) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (attackername, attackerstart, attackerend, victimname, victimstart, victimend, processname, pid, rip, address, functionname, action, protection, datetime.datetime.now()))

            last_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO PROCESS_TIMELINE_EVENT (ID_TIMELINE, EVENTTYPE, EVENT_ID) VALUES (?, ?, ?)",
                (timeline_id, 4, last_id)
            )

            conn.commit()
            if action == 1:
                self.update_timeline_state(timeline_id, 2, True)
            else:
                self.update_timeline_state(timeline_id, 3, True)

            ans = last_id
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans

    def get_alert_by_alert_id(self, alert_id, acquired = False):
        if not acquired:
            DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = None
        try:
            cursor = conn.cursor()
            cursor2 = conn.cursor()
            cursor.execute("SELECT * FROM MODULE_ALERT_EVENT WHERE ID = ?", (alert_id,))
            row_1 = cursor.fetchone()
            instructions = []
            cursor2.execute("SELECT * FROM MODULE_ALERT_INSTRUCTION WHERE ALERT_ID = ?", (alert_id,))
            for instrux in cursor2:
                instructions.append(self._instruction_to_dict(instrux[1], instrux[2], instrux[3]))
            ans = self._mod_alert_event_to_dict(row_1[0], row_1[1], row_1[2], row_1[3], row_1[4], row_1[5], row_1[6],
                                                      row_1[7], row_1[8], row_1[9], row_1[10], row_1[11], row_1[12],
                                                      row_1[13], instructions)
        except:

            traceback.print_exc()
            conn.rollback()


        conn.close()
        if not acquired:
            DBHandler.instance.glock.release()
        return ans
    def create_instruction(self, mnemonic, instrux, length, event_id):
        """
        MNEMONIC INTEGER,
                                  INSTRUX  TEXT,
                                  LENGTH   INTEGER,
                                  ALERT_ID INTEGER
        :param mnemonic:
        :param instrux:
        :param length:
        :param event_id:
        :return:
        """
        DBHandler.instance.glock.acquire()
        ans = None
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO MODULE_ALERT_INSTRUCTION(MNEMONIC, INSTRUX, LENGTH, ALERT_ID) VALUES (?,?,?,?)",
                (mnemonic, instrux, length, event_id))

            conn.commit()
            ans = cursor.lastrowid
        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans
    ############################################################################
    ####################                                    ####################
    ####################         PROTECTED PROCESSES        ####################
    ####################                                    ####################
    ############################################################################

    def create_protected_process(self, processname, mask):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO PROTECTED_PROCESSES(PROCESSNAME, MASK) VALUES (?,?)",
                (processname, mask))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    def remove_protected_process(self, processname):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM PROTECTED_PROCESSES WHERE PROCESSNAME = ?",
                (processname,))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    def get_all_protected_processes(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = []
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM PROTECTED_PROCESSES")
            for row in cursor:
                ans.append({
                  "processname": row[1],
                  "mask": row[2]
                })

        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans
    def change_protected_process(self, processname, newmask):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE PROTECTED_PROCESSES SET MASK = ? WHERE PROCESSNAME = ?",
                (processname, newmask))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    ############################################################################
    ####################                                    ####################
    ####################         EXCEPTIONS                 ####################
    ####################                                    ####################
    ############################################################################

    def create_exception(self, alert_id):
        # also mark all timelines with alert_id as excepted
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO EXCEPTIONS(ALERT_ID) VALUES (?)",
                (alert_id, ))

            cursor.execute("UPDATE ALERT_TIMELINE SET EXCEPTED = ? WHERE ALERT_ID = ?", (1, alert_id))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()


    def remove_exception(self, exception_id):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM EXCEPTIONS WHERE ID = ?",
                (exception_id,))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    def get_all_exceptions(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = []
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM EXCEPTIONS")

            for row in cursor:
                ans.append({
                    "id": row[0],
                    "alert": self.get_alert_by_alert_id(row[1], acquired=True)
                })

        except:

            traceback.print_exc()
            conn.rollback()

        conn.close()
        DBHandler.instance.glock.release()
        return ans
    ############################################################################
    ####################                                    ####################
    ####################         BLOCKED DLLS               ####################
    ####################                                    ####################
    ############################################################################

    def create_blocked_dll(self, dll_name):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO BLOCKED_DLLS(DLL_NAME) VALUES (?)",
                (dll_name,))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    def removed_blocked_dll(self, removed_dll_name):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM BLOCKED_DLLS WHERE DLL_NAME = ?",
                (removed_dll_name,))

            conn.commit()
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()

    def get_all_blocked_dlls(self):
        DBHandler.instance.glock.acquire()
        conn = sqlite3.connect("mhvev.db")
        ans = []
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM BLOCKED_DLLS")

            for row in cursor:
                ans.append({"dll_name": row[1]})
        except:
            traceback.print_exc()
            conn.rollback()
        conn.close()
        DBHandler.instance.glock.release()
        return ans


