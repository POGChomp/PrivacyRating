import socket
import subprocess
import sys
from math import ceil

from PyQt6 import QtWidgets
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QFileDialog, QDialog

import config
import methods
from apkscan import Ui_MainWindow
from nofiledialog import Ui_Dialog


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    """Loading and setting up the Main-GUI

    Main-GUI was pre-design with Qt Designer and converted from .ui to .py for better usage.
    Changes shall only be made within Qt Designer.
    To convert the changed .ui file again, just type

    pyuic6 apkscan.ui -o apkscan.py

    in the terminal.
    """

    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        self.setupUi(self)

        self.setWindowTitle("APK Analyzer")
        self.gradePlace.setPixmap(QPixmap("./grades/Hintergrund.png"))

        self.selectFile.clicked.connect(self.load_apk)
        self.startProcess.clicked.connect(self.start_analysis)

    def load_apk(self):
        """Method to select an APK

        This method triggers the QFileDialog to select an APK-file. The path to the file is set as text for
        the QLineEdit Widget (displayFile)"""

        fname = QFileDialog.getOpenFileNames(self, 'Open file', '~/home/', "APK files (*.apk)")

        # fname comes as a tuple, where the first element is a list that contains the string
        # if fname[0] is empty, its boolean value is FALSE
        if not fname[0]:
            # Catches a potential crash, if QFileDialog is closed without a file selected
            print("No file selected.")
        else:
            self.displayFile.setText(fname[0][0])

    def start_analysis(self):

        ## Debugging Vars ##
        mobsf_is_checked = self.mobsf.isChecked()
        flow_is_checked = self.flow.isChecked()
        not_at_least_one_tool = not (mobsf_is_checked | flow_is_checked)

        text_is_not_empty = bool(self.displayFile.text())
        file_ends_with_apk = self.displayFile.text().endswith(".apk")
        no_apk_is_selected = not (text_is_not_empty & file_ends_with_apk)

        # if one part is missing (no tools or no file selected) an QDialog is triggered with a warning message
        # else the analysis starts
        if not_at_least_one_tool:
            print("Please select at least one tool")

            dialog = NoToolDialog(self)
            dialog.exec()

        elif no_apk_is_selected:
            print("Please select APK file")

            dialog = NoFileDialog(self)
            dialog.exec()

        else:
            # first checks if MobSF is already running on the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # int(config.SERVER[-4:]) fetches the last four digits from SERVER using slices and converts it to int to
            # get the pre-defined port
            result = sock.connect_ex(('127.0.0.1', int(config.SERVER[-4:])))
            if result == 0:

                print("Port is open")

            else:

                print("Port is closed")

                subprocess.Popen(
                    "mate-terminal -e '{MOBSFPATH} {SERVER}'".format(MOBSFPATH=config.MOBSFPATH,
                                                                     SERVER=config.SERVER[7:]),
                    shell=True)

                # program has to wait a short time, so MobSF can start up. 5 seconds should be enough.
                methods.idle(5)

            response = methods.upload(self.displayFile.text(), config.SERVER, config.APIKEY)
            scan_output = methods.scan(response, config.SERVER, config.APIKEY)

            permissions = methods.permissions2df(scan_output)
            trackers = methods.trackers2df(scan_output)

            dangerous_permission_count = len(permissions[permissions['status'] == 'dangerous'])
            tracker_count = len(trackers)

            perms_grade = methods.switch_grade(dangerous_permission_count)
            tracks_grade = methods.switch_grade(tracker_count)

            mean_grade = ceil((perms_grade + tracks_grade) / 2)

            image = "./grades/%s" % config.IMAGES[methods.switch_image(mean_grade)]

            self.gradePlace.setPixmap(QPixmap(image))


class NoFileDialog(QDialog, Ui_Dialog):
    """No APK selected dialog.

    Dialog-GUI was pre-designed with Qt Designer and converted from .ui to .py for better usage.
    Changes shall only be made within Qt Designer.
    To convert the changed .ui file again, just type

    pyuic6 nofiledialog.ui -o nofiledialog.py

    in the terminal.
    """

    def __init__(self, parent=None):
        super(NoFileDialog, self).__init__(parent)
        self.setupUi(self)


class NoToolDialog(QDialog, Ui_Dialog):
    """No Tool selected dialog.

    This Dialog overrides the NoFileSelected Dialog. For more information please look at the class NoFileDialog()"""

    def __init__(self, parent=None):
        super(NoToolDialog, self).__init__(parent)
        self.setupUi(self)

        self.setWindowTitle("No Tool")
        self.infoText.setText("Please select at least one tool.")


if __name__ == "__main__":

    # Create the application
    app = QtWidgets.QApplication(sys.argv)
    # Create and show the application's main window
    window = MainWindow()
    window.show()
    # Run the application's main loop
    sys.exit(app.exec())
