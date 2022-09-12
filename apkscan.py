# Form implementation generated from reading ui file 'apkscan.ui'
#
# Created by: PyQt6 UI code generator 6.3.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(563, 253)
        MainWindow.setMinimumSize(QtCore.QSize(150, 150))
        MainWindow.setMaximumSize(QtCore.QSize(10000, 10000))
        MainWindow.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.infoText = QtWidgets.QLabel(self.centralwidget)
        self.infoText.setObjectName("infoText")
        self.verticalLayout.addWidget(self.infoText)
        self.displayFile = QtWidgets.QLineEdit(self.centralwidget)
        self.displayFile.setInputMask("")
        self.displayFile.setReadOnly(False)
        self.displayFile.setObjectName("displayFile")
        self.verticalLayout.addWidget(self.displayFile)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.selectFile = QtWidgets.QPushButton(self.centralwidget)
        self.selectFile.setObjectName("selectFile")
        self.horizontalLayout.addWidget(self.selectFile)
        self.startProcess = QtWidgets.QPushButton(self.centralwidget)
        self.startProcess.setObjectName("startProcess")
        self.horizontalLayout.addWidget(self.startProcess)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.mobsf = QtWidgets.QCheckBox(self.centralwidget)
        self.mobsf.setChecked(True)
        self.mobsf.setObjectName("mobsf")
        self.verticalLayout_2.addWidget(self.mobsf)
        self.flow = QtWidgets.QCheckBox(self.centralwidget)
        self.flow.setObjectName("flow")
        self.verticalLayout_2.addWidget(self.flow)
        self.verticalLayout.addLayout(self.verticalLayout_2)
        self.horizontalLayout_2.addLayout(self.verticalLayout)
        self.gradePlace = QtWidgets.QLabel(self.centralwidget)
        self.gradePlace.setMinimumSize(QtCore.QSize(150, 150))
        self.gradePlace.setMaximumSize(QtCore.QSize(150, 150))
        self.gradePlace.setBaseSize(QtCore.QSize(0, 0))
        self.gradePlace.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.gradePlace.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.gradePlace.setScaledContents(True)
        self.gradePlace.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.gradePlace.setObjectName("gradePlace")
        self.horizontalLayout_2.addWidget(self.gradePlace)
        self.verticalLayout_3.addLayout(self.horizontalLayout_2)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 563, 23))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.infoText.setText(_translate("MainWindow", "Select APK and tools that should be used for analysis:"))
        self.displayFile.setPlaceholderText(_translate("MainWindow", "/path/to/file.apk"))
        self.selectFile.setText(_translate("MainWindow", "Select APK"))
        self.startProcess.setText(_translate("MainWindow", "Start Analysis"))
        self.startProcess.setShortcut(_translate("MainWindow", "Return"))
        self.mobsf.setText(_translate("MainWindow", "MobSF"))
        self.flow.setText(_translate("MainWindow", "FlowDroid"))
        self.gradePlace.setText(_translate("MainWindow", "Privacy Grade"))