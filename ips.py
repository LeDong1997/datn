import sys, os
import psutil
import random
import numpy as np
import time
import subprocess
import json
import socket
import struct
import threading
import random
import webbrowser
import math
import datetime
import requests

import win32ui
import win32gui
import win32con
import win32api

from time import sleep,mktime,strftime
from json.decoder import JSONDecoder
from PyQt5.Qt import Qt, QFont
from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import pyqtSlot, QTimeLine, pyqtSignal, QThread
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QAction, QLineEdit, QMessageBox, QTableWidgetItem, QAbstractItemView, QMessageBox
from PyQt5.QtChart import QChart, QChartView, QValueAxis, QBarCategoryAxis, QBarSet, QBarSeries, QLineSeries
from PyQt5.QtGui import QPainter, QPixmap
from mplwidget import*
from subprocess import check_output as qx

 
qtCreatorFile = "ips.ui" # Enter file here.
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
Ui_MainWindowLoading, QtBaseClassLoading = uic.loadUiType("loading.ui")


check_thread_chart_network = 0
check_thread_chart_cpu = 0
check_thread_chart_ram = 0
check_thread_process = 0
isStopQuickScan = 2
isStopFullScan = 2
passwordCrpyt = ""
eventCrypt = ""
pathCrypt = ""
listScan = []
listVirusFullScan = []
listVirusQuickScan = []
listVirusSelectiveScan = []
isListVirus = ""


runThreadChartNetWorks = []
gcard = "";


class LoadingApp(QMainWindow, Ui_MainWindowLoading, QWidget):
    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindowLoading.__init__(self)
        self.setupUi(self)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.screenShape = QDesktopWidget().screenGeometry()
        self.setFixedSize(self.screenShape.width(), self.screenShape.height())
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        app = openMainWindow(self)
        app.exitLoading.connect(self.exitLoading)
        app.start()
        app.exec_()
        sys.exit(app.exec_())

    def exitLoading(self):
        self.app = MyApp()
        self.app.show()
        self.close()


class openMainWindow (QThread):
    exitLoading = pyqtSignal()
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        time.sleep(0.5)
        self.exitLoading.emit()


		
class MyApp(QMainWindow, Ui_MainWindow, QWidget):

    def fcntl(fd, op, arg=0):
        return 0

    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)

        self.setupUi(self)
        self.setFixedSize(956, 672)
        self.setWindowTitle("Host based IPS")
        self.setWindowIcon(QtGui.QIcon("icon/logo_ips.png"))
        # self.setExecutionPolicy()
        # self.updateNetstat()
        # self.runNetworkInfo()
        # self.ruleManagement()
        self.styleTable()
        self.baseLink()
        # self.infoHardDisk()
        # self.inforDisk()
        # self.runInfoApplication()
        self.show_report_list()
        self.integrity()

        # -----------------chart Threads ------------------#

        # threadClamav = ThreadClamav(self)
        # threadClamav.start()

        # runThreadChartCPU = ThreadChartCPU(self)
        # runThreadChartCPU.start()

        # runThreadChartRAM = ThreadChartRAM(self)
        # runThreadChartRAM.start() 

        runThreadscanIntegrity = ThreadscanIntegrity(self)
        runThreadscanIntegrity.updateReportScan.connect(self.reportScan)
        runThreadscanIntegrity.start()

        # runThreadscanMonitor = ThreadscanMonitor(self)
        # runThreadscanMonitor.start()

        # runThreatProcess = ThreadTableProcess(self)
        # runThreatProcess.updateProcess.connect(self.updateProcessListThread)
        # runThreatProcess.start()

        # runThreadUpdateInfo = ThreadUpdateInfo(self)
        # runThreadUpdateInfo.updateInfo.connect(self.updateInfo)
        # runThreadUpdateInfo.start()

        # runThreadStartClamd = ThreadClamdStart(self)
        # runThreadStartClamd.start()



        # ========================= style line chart =========================#
        self.chart_network.canvas.figure.set_facecolor("#121416")
        # self.chart_network.canvas.axes.patch.set_facecolor('black')
        self.chart_network.canvas.axes.patch.set_alpha(0.0)
        self.chart_network.canvas.axes.figure.set_facecolor('None')
        self.chart_network.canvas.axes.tick_params(labelcolor='#c7c7c9')
        self.chart_network.canvas.axes.set_xticklabels([])
        self.chart_network.canvas.axes.spines['top'].set_color('None')
        self.chart_network.canvas.axes.spines['left'].set_color('gray')
        self.chart_network.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_network.canvas.axes.spines['right'].set_color('None')
        self.chart_network.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_network.canvas.axes.spines['bottom'].set_alpha(0.2)

        self.chart_cpu.canvas.figure.set_facecolor("#121416")
        # self.chart_cpu.canvas.axes.patch.set_facecolor('black')
        self.chart_cpu.canvas.axes.patch.set_alpha(0.0)
        self.chart_cpu.canvas.axes.figure.set_facecolor('None')
        self.chart_cpu.canvas.axes.tick_params(labelcolor='#c7c7c9')
        # self.chart_cpu.canvas.axes.set_xticklabels([])
        self.chart_cpu.canvas.axes.spines['top'].set_color('None')
        self.chart_cpu.canvas.axes.spines['left'].set_color('gray')
        self.chart_cpu.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_cpu.canvas.axes.spines['right'].set_color('None')
        self.chart_cpu.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_cpu.canvas.axes.spines['bottom'].set_alpha(0.2)

        self.chart_ram.canvas.figure.set_facecolor("#121416")
        # self.chart_ram.canvas.axes.patch.set_facecolor('black')
        self.chart_ram.canvas.axes.patch.set_alpha(0.0)
        self.chart_ram.canvas.axes.figure.set_facecolor('None')
        self.chart_ram.canvas.axes.tick_params(labelcolor='#c7c7c9')
        # self.chart_ram.canvas.axes.set_xticklabels([])
        self.chart_ram.canvas.axes.spines['top'].set_color('None')
        self.chart_ram.canvas.axes.spines['left'].set_color('gray')
        self.chart_ram.canvas.axes.spines['left'].set_alpha(0.2)
        self.chart_ram.canvas.axes.spines['right'].set_color('None')
        self.chart_ram.canvas.axes.spines['bottom'].set_color('gray')
        self.chart_ram.canvas.axes.spines['bottom'].set_alpha(0.2)

    # ============================ end style line chart ===========================#



    def baseLink(self):
        self.button_detail.clicked.connect(lambda: webbrowser.open('https://dascam.com.vn'))

        self.backHome1.mouseReleaseEvent=self.changeTabTo0
        self.backHome2.mouseReleaseEvent=self.changeTabTo12
        self.backHome3.mouseReleaseEvent=self.changeTabTo0
        self.backHome8.mouseReleaseEvent=self.changeTabTo0
        self.backHome10.mouseReleaseEvent=self.changeTabTo0
        self.backHome12.mouseReleaseEvent=self.changeTabTo0
        self.backHome13.mouseReleaseEvent=self.changeTabTo0

        # Change Host IPS tab
        self.function1.mouseReleaseEvent=self.changeTabTo4
        self.function2.mouseReleaseEvent=self.changeTabTo12
        self.function3.mouseReleaseEvent=self.changeTabTo13
        self.function6.mouseReleaseEvent=self.changeTabTo1
        self.function4.mouseReleaseEvent=self.changeTabTo8
        self.function5.mouseReleaseEvent=self.changeTabTo10

        #click disk detail 
        self.disk_detail.mouseReleaseEvent=self.changeTabTo2

        # Change network_management tab
        self.firewall.mouseReleaseEvent=self.changeNetworkManagementTo_1
        self.firewall_module_tab.mouseReleaseEvent=self.changeNetworkManagementTo_0
        self.logManagement.mouseReleaseEvent=self.changeNetworkManagementTo_2
        self.information.mouseReleaseEvent=self.changeNetworkManagementTo_3
        self.rule_management.mouseReleaseEvent=self.changeNetworkManagementTo_4
        # self.dns.mouseReleaseEvent=self.changeNetworkManagementTo_5
        self.end_task.clicked.connect(self.killProcess)
        self.end_task_2.clicked.connect(self.killProcessApp)

        # Change This PC tab
        self.license.mouseReleaseEvent=self.changeThisPCTo_0
        self.info_pc.mouseReleaseEvent=self.changeThisPCTo_1

        # rule management
        self.rule_in.mouseReleaseEvent=self.changeTabTo17
        self.rule_out.mouseReleaseEvent=self.changeTabTo18
        self.rule_program.mouseReleaseEvent=self.changeTabTo19
        self.back_rule_management.mouseReleaseEvent=self.changeTabTo1
        self.back_rule_management_1.mouseReleaseEvent=self.changeTabTo1
        self.back_rule_management_2.mouseReleaseEvent=self.changeTabTo1
        self.back_to_inRule.mouseReleaseEvent=self.changeTabTo17
        self.back_to_outRule.mouseReleaseEvent=self.changeTabTo18
        self.back_to_programRule.mouseReleaseEvent=self.changeTabTo19
        #click create new rule
        self.add_rule_in.mouseReleaseEvent=self.changeTabTo3
        self.add_rule_out.mouseReleaseEvent=self.changeTabTo7
        self.add_rule_program.mouseReleaseEvent=self.changeTabTo20
        self.create_in_rule.clicked.connect(self.createNewInRule)
        self.create_out_rule.clicked.connect(self.createNewOutRule)
        self.create_program_rule.clicked.connect(self.createNewProgramRule)
        #restore new rule
        self.restore_new_rule1.clicked.connect(self.clearDataInputInRule)
        self.restore_new_rule2.clicked.connect(self.clearDataInputOutRule)
        self.restore_new_rule3.clicked.connect(self.clearDataProgramRule)
        #reomve rule
        self.remove_rule.mouseReleaseEvent=self.removeRuleIn
        self.remove_rule_out.mouseReleaseEvent=self.removeRuleOut
        self.remove_rule_program.mouseReleaseEvent=self.removeRuleProgram
        #change state rule
        self.change_state_in.mouseReleaseEvent=self.changeStateInRule
        self.change_state_out.mouseReleaseEvent=self.changeStateOutRule
        self.change_state_program.mouseReleaseEvent=self.changeStateProgramRule


        #change file sytem protect tab 
        self.file_system.mouseReleaseEvent = self.changeTabTo5
        self.folder_system.mouseReleaseEvent = self.changeTabTo15
        self.back_file_system.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_2.mouseReleaseEvent = self.changeTabTo4
        self.back_file_system_3.mouseReleaseEvent = self.changeTabTo4
        self.integrity_check.mouseReleaseEvent = self.changeTabTo6
        self.Monitor_file_system.mouseReleaseEvent= self.changeTabTo14
        self.back_file_system_4.mouseReleaseEvent= self.changeTabTo4
        self.progressBar_folder.hide()
        self.alert_hash.hide()
        self.log_reports.mouseReleaseEvent= self.changeTabTo16
        self.log_reports_monitor.mouseReleaseEvent = self.showTableReportMonitor
        self.back_integrity.mouseReleaseEvent = self.changeTabTo6
        self.remove_file.clicked.connect(self.removePath)
        self.update_file.clicked.connect(self.updatePath)
        self.remove_file_monitor.clicked.connect(self.removePathMonitor)
        self.update_file_monitor.clicked.connect(self.updatePathMonitor)


        #change applications tab
        self.application_1.mouseReleaseEvent=self.changeApplicationTo1
        self.application_2.mouseReleaseEvent=self.changeApplicationTo2
        self.application_3.mouseReleaseEvent=self.changeApplicationTo3
        self.back_to_app.mouseReleaseEvent=self.changeTabTo8
        self.show_security_hole.mouseReleaseEvent=self.showASecurityHole
        self.back_to_application.mouseReleaseEvent=self.changeTabTo9
        self.launch.mouseReleaseEvent=self.runApplication
        self.remove_app.mouseReleaseEvent=self.removeApplication

        #change tab malware
        self.full_scan.mouseReleaseEvent=self.changeMalwareTabTo0
        self.quick_scan.mouseReleaseEvent=self.changeMalwareTabTo1
        self.selective_scan.mouseReleaseEvent=self.changeMalwareTabTo2
        self.external_device_scan.mouseReleaseEvent=self.changeMalwareTabTo3
        #function quick scan
        self.quick_scan_stop.hide()
        self.quick_scan_end.hide()
        self.info_quick_scan.hide()
        self.quick_scan_stop.setEnabled(False)
        self.quick_scan_end.setEnabled(False)
        self.quick_scan_start.mouseReleaseEvent=self.quickScanStart
        self.quick_scan_stop.mouseReleaseEvent=self.quickScanStop
        self.quick_scan_end.mouseReleaseEvent=self.quickScanEnd
        #function full scan
        self.full_scan_stop.hide()
        self.full_scan_end.hide()
        self.info_full_scan.hide()
        self.full_scan_stop.setEnabled(False)
        self.full_scan_end.setEnabled(False)
        self.full_scan_start.mouseReleaseEvent=self.fullScanStart
        self.full_scan_stop.mouseReleaseEvent=self.fullScanStop
        self.full_scan_end.mouseReleaseEvent=self.fullScanEnd
        self.show_detail_full_scan.mouseReleaseEvent=lambda x: self.showListVirusScan("full_scan")
        self.show_detail_quick_scan.mouseReleaseEvent=lambda x: self.showListVirusScan("quick_scan")
        self.show_detail_selective_scan.mouseReleaseEvent=lambda x: self.showListVirusScan("selective_scan")
        self.back_to_scan.mouseReleaseEvent=self.changeTabTo13
        #import file/folder to scan
        self.add_file_scan.mouseReleaseEvent = self.addFileScan
        self.add_folder_scan.mouseReleaseEvent = self.addFolderScan
        self.add_folder_scan_box.mouseReleaseEvent = self.addFolderScan
        self.widget_scan.hide()
        self.selective_scan_start.mouseReleaseEvent=self.selectiveScanStart
        self.restore_list_path.hide()
        self.restore_list_path.mouseReleaseEvent=self.restoreListPath
        #remove virus
        self.remove_virus.clicked.connect(self.removeVirus)


        #tab report
        self.back_to_report.mouseReleaseEvent=self.changeReportToMain
        self.change_show_report_list.mouseReleaseEvent=self.showReprotList
        self.show_table_report_monitor.mouseReleaseEvent=self.showTableReportMonitor
        self.back_to_report_2.mouseReleaseEvent=self.changeReportToMain
        self.show_table_report_integrity.mouseReleaseEvent=self.showTableReportIntegrity
        self.back_to_report_3.mouseReleaseEvent=self.changeReportToMain
        self.show_table_report_virus.mouseReleaseEvent=self.showTableReportVirus
        self.back_to_report_4.mouseReleaseEvent=self.changeReportToMain



        #scan file
        self.import_file.mouseReleaseEvent=self.scanFile
        self.box_function.toggled.connect(self.changeState)
        #star_encrypt_file
        self.start_crypt.clicked.connect(lambda: self.startCrypt(self.file_info.toPlainText()))
        #scan folder
        self.import_folder.mouseReleaseEvent=self.scanFolder
        self.box_function_2.toggled.connect(self.changeStateFolder)
        #star_encrypt_file
        self.start_crypt_folder.clicked.connect(lambda: self.startCryptFolder(self.folder_info.toPlainText()))
        #improt file/folder/xml/hashFile intergitry
        self.select_file.mouseReleaseEvent = self.addFile
        self.select_folder.mouseReleaseEvent = self.addFolder
        self.select_file_xml.mouseReleaseEvent = self.addXml
        self.select_hash.mouseReleaseEvent=self.hashFile
        self.hash.hide()
        self.code_hash.hide()
        #improt file/folder monitor
        self.select_file_monitor.mouseReleaseEvent = self.addFileMonitor
        self.select_folder_monitor.mouseReleaseEvent = self.addFolderMonitor


        # info hard disk
        self.disk_1.hide()
        self.disk_2.hide()
        self.disk_3.hide()
        self.disk_4.hide()

    # ================================== functions of system =====================================#
    def changeTabTo0(self, instance):
        # FaderWidget(self.main.currentWidget(),self.main.widget(0))
        self.main.setCurrentIndex(0)
    def changeTabTo1(self, instance):
        # FaderWidget(self.main.currentWidget(),self.main.widget(1))
        self.main.setCurrentIndex(1)
    
    def changeTabTo2(self, instance):
        self.main.setCurrentIndex(2)
    def changeTabTo3(self, instance):
        self.main.setCurrentIndex(3)
        self.clearDataInputInRule()
    def changeTabTo4(self, instance):
        self.main.setCurrentIndex(4)
    def changeTabTo5(self, instance):
        self.main.setCurrentIndex(5)
    def changeTabTo6(self,instance):
        self.main.setCurrentIndex(6)
    def changeTabTo7(self, instance):
        self.main.setCurrentIndex(7)
        self.clearDataInputOutRule()
    def changeTabTo8(self, instance):
        self.main.setCurrentIndex(8)
    def changeTabTo9(self, instance):
        self.main.setCurrentIndex(9)
    def changeTabTo10(self, instance):
        self.main.setCurrentIndex(10)
    def changeTabTo12(self, instance):
        self.main.setCurrentIndex(12)
    def changeTabTo13(self, instance):
        self.main.setCurrentIndex(13)
    def changeTabTo14(self, instance):
        self.main.setCurrentIndex(14)
    def changeTabTo15(self, instance):
        self.main.setCurrentIndex(15)
    def changeTabTo16(self, instance):
        self.main.setCurrentIndex(16)
        self.showDetailReportIntegrity()
    def changeTabTo17(self, instance):
        self.main.setCurrentIndex(17)
    def changeTabTo18(self, instance):
        self.main.setCurrentIndex(18)
    def changeTabTo19(self, instance):
        self.main.setCurrentIndex(19)
    def changeTabTo20(self, instance):
        self.main.setCurrentIndex(20)
        self.clearDataProgramRule()
    def changeTabTo21(self, instance):
        self.main.setCurrentIndex(21)
    def changeTabTo22(self, instance):
        self.main.setCurrentIndex(22)
    def changeTabTo23(self, instance):
        self.main.setCurrentIndex(23)
    def changeTabTo24(self, instance):
        self.main.setCurrentIndex(24)
    def changeTabTo25(self, instance):
        self.main.setCurrentIndex(25)




    def changeNetworkManagementTo_0(self, instance):
        self.mainSetting.setCurrentIndex(0)
    def changeNetworkManagementTo_1(self, instance):
        # FaderWidget(self.mainSetting.currentWidget(),self.mainSetting.widget(1))
        self.mainSetting.setCurrentIndex(1)
    def changeNetworkManagementTo_2(self, instance):
        self.mainSetting.setCurrentIndex(2)
    def changeNetworkManagementTo_3(self, instance):
        self.mainSetting.setCurrentIndex(3)
    def changeNetworkManagementTo_4(self, instance):
        self.mainSetting.setCurrentIndex(4)
    def changeNetworkManagementTo_5(self, instance):
        self.mainSetting.setCurrentIndex(5)
        # threadInfoNetwork = infoNetwork(MyApp())
        # threadInfoNetwork.start()

    def setExecutionPolicy(self):
        p = subprocess.Popen(["powershell.exe" ,".\powershell\setup.ps1"], stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()

    def ruleManagement(self):
        self.showIncomingTraffic()
        self.showOutTraffic()
        self.showProgramTraffic()
        self.hideColumnsRule()
    def runNetworkInfo(self):
        self.netinfo()
        self.getConigHardware()
        # self.getProcessList()
    def runManagement(self):
    	self.dnsQueryList()
    	self.dgaLog()
    	# self.showBlackList()
	    # self.showWhiteList()


    def changeThisPCTo_0(self,instance):
        self.ThisPC.setCurrentIndex(0)
    def changeThisPCTo_1(self,instance):
        self.ThisPC.setCurrentIndex(1)


    def changeApplicationTo1(self, instance):
        self.application_stacked.setCurrentIndex(0)
    def changeApplicationTo2(self, instance):
        self.application_stacked.setCurrentIndex(1)
    def changeApplicationTo3(self, instance):
        self.application_stacked.setCurrentIndex(2)

    def changeMalwareTabTo0(self,instance): 
        self.malwareStackedWidget.setCurrentIndex(0)
    def changeMalwareTabTo1(self,instance): 
        self.malwareStackedWidget.setCurrentIndex(1)
    def changeMalwareTabTo2(self,instance): 
        self.malwareStackedWidget.setCurrentIndex(2)
    def changeMalwareTabTo3(self,instance): 
        self.malwareStackedWidget.setCurrentIndex(3)
    

    def changeReportToMain(self, instance):
        self.main.setCurrentIndex(10)
    def showReprotList(self,instance):
        self.main.setCurrentIndex(11)

    
    def runInfoApplication(self):
        # self.getProcessApp()
        self.showListApplications()

    def getInfoApp(self,instance):
        self.main.setCurrentIndex(9)

    def integrity(self):
        self.showPathTable()
        self.updatePathMonitor()

    # def closeEvent(self, event):
    #     sys.exit()


    
    # ================================== end functions of system =====================================#






    @pyqtSlot()

    ############################################### File system protection #######################################################
    # =============================================file system================================================================#

    def scanFile(self, instance):
        option = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)

        if fileName:
            self.file_system_protection.setCurrentIndex(0)
            self.message_scan.setVisible(False)
            self.select_function.setText("Thực hiện mã hóa")
            self.file_info.setText(fileName)

    def changeState(self):
        if self.box_function.isChecked():
            self.select_function.setText("Thực hiện giải hóa")
        else:
            self.select_function.setText("Thực hiện mã hóa")


    def startCrypt(self, path):
        path = path.replace("/","\\")
        self.message_scan.setVisible(False)
        password = self.confirmPassword()
        if password == "canceled":
            self.start_crypt_folder.setEnabled(True)
            return
        else:
            # cmd = ''
            if self.box_function.isChecked():
                self.decryptFile(path, password, 0)
            else:
                cmd = 'python script\\file_system\\crypto.py -e -f ' '"'+path+'"' + ' "'+password+'"'
                self.encryptFile(cmd)


    def encryptFile(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        state = str(output).find("Done encrypt file")
        # print(str(output), state)
        if state != -1:   
            self.message_scan.setVisible(True)
            self.message_scan.setText("Mã hóa thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
        else:
            self.message_scan.setVisible(True)
            self.message_scan.setText("Mã hóa không thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");


    def decryptFile(self, path, password, Option):
        cmd = 'python script\\file_system\\crypto.py -d -f ' '"'+path+'"' + ' "'+password+'"'+' '+str(Option)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        state = str(output).find("Done decrypt file.")
        print(str(output), state)
        if state != -1:   
            self.message_scan.setVisible(True)
            self.message_scan.setText("Giải mã thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/check.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");
        elif(str(output).find("Confirm override") != -1):
            status = self.confirmBox("Tệp tin giải mãi đã tồn tại, bạn có muốn ghi đè?")
            if(status == 1):
                self.decryptFile(path, password, 2)
        else:
            self.message_scan.setVisible(True)
            self.message_scan.setText("Giải mã không thành công")
            self.message_scan.setIcon(QtGui.QIcon("icon/unnamed.png"))
            self.message_scan.setStyleSheet("QPushButton {background-color: transparent;text-align: left;}");


    def confirmPassword(self):
        dlg = QInputDialog()
        text, result = dlg.getText(self, "Nhập mật khẩu",
                                     "New password:", QLineEdit.Normal)

        if result and text:
            return text
        else:
            return "canceled"


    def confirmBox(self, mess):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(mess)
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg.setWindowFlags(QtCore.Qt.CustomizeWindowHint)
        ret = retval = msg.exec_()
        if ret == QMessageBox.Ok:
            return 1
        else:
            return 0



    # =============================================folder system================================================================#
                      

    def scanFolder(self, instance):
        option = QFileDialog.Options()
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory",
                                             "/home",
                                             QFileDialog.ShowDirsOnly
                                             | QFileDialog.DontResolveSymlinks)

        if folderName:
            self.message_scan_2.setVisible(False)
            self.select_function_2.setText("Thực hiện mã hóa")
            self.folder_info.setText(folderName)

    def changeStateFolder(self):
        if self.box_function_2.isChecked():
            self.select_function_2.setText("Thực hiện giải mã")
        else:
            self.select_function_2.setText("Thực hiện mã hóa")

    def startCryptFolder(self, path):
        self.message_scan_2.setVisible(False)
        self.start_crypt_folder.setEnabled(False)
        password = self.confirmPassword()
        path = path.replace("/","\\")
        if password == "canceled":
            self.start_crypt_folder.setEnabled(True)
            return
        else:
            cmd = ''
            global pathCrypt
            global eventCrypt
            global passwordCrpyt
            if self.box_function_2.isChecked():
                event = "decode"
            else:
                event = "encode"
            pathCrypt = path
            eventCrypt = event
            passwordCrpyt = password
            self.path_crypt.setText("")
            self.progressBar_folder.setValue(0)
            self.progressBar_folder.setVisible(True)
            self.message_scan_2.setVisible(True)
            self.progressBar_folder.setMaximum(100)
            self.message_scan_2.setIcon(QtGui.QIcon())
            runThreadEncryptFolder = ThreadEncryptFolder(self)
            runThreadEncryptFolder.updatePath.connect(self.path_crypt.setText)
            runThreadEncryptFolder.updateProcessBar.connect(self.progressBar_folder.setValue)
            runThreadEncryptFolder.updateIndex.connect(self.message_scan_2.setText)
            runThreadEncryptFolder.completeCrypt.connect(self.completeCryptFolder)
            runThreadEncryptFolder.start()

    def completeCryptFolder(self):
        self.progressBar_folder.setValue(100)
        self.message_scan_2.setIcon(QtGui.QIcon("icon/check.png"))
        self.start_crypt_folder.setEnabled(True)


    # =============================================Kiem tra tinh toan ven ================================================================#

    def addFile(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_file.setText(fileName)
            cmd = 'python script\\file_system\\demo_integrity.py -i ' + '"'+fileName+'"' +' 0'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()


    def addFolder(self, instance):
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory","/home",QFileDialog.ShowDirsOnly|QFileDialog.DontResolveSymlinks)
        if folderName:
            self.path_folder.setText(folderName)
            cmd = 'python script\\file_system\\demo_integrity.py -i ' + '"'+folderName+'"' +' 1'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()


    def addXml(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','*.xml',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_xml.setText(fileName)
            cmd = 'python script\\file_system\\demo_integrity.py -x ' + '"'+fileName+'"'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTable()

    def hashFile(self, instance):
        self.alert_hash.hide()
        self.hash.hide()
        self.code_hash.hide()
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_hash_file.setText(fileName)
            cmd = 'python script\\file_system\\demo_integrity.py -m ' + '"'+fileName+'"'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                state = json.loads(output.decode('ASCII'))['result']
                data = json.loads(output.decode('ASCII'))['hash_str']
                if(state == True):
                    self.alert_hash.setVisible(True)
                    self.hash.setVisible(True)
                    self.code_hash.setVisible(True)
                    self.code_hash.setText(data)

                else:
                    self.alert_hash.setIcon(QtGui.QIcon("icon/unnamed.png"))
                    self.alert_hash.setText("Không thành công")



    def showPathTable(self):
        cmd = 'python script\\file_system\\demo_integrity.py -l'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        if(p_status == 0):
            data = json.loads(output.decode('ASCII'))['check_list']
            self.path_list.setColumnCount(2)
            self.path_list.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[2])
                self.path_list.setCellWidget(i,0,path)
                self.path_list.setItem(i, 1, QTableWidgetItem(str(data[1])))
                i = i + 1
            self.path_list.setColumnHidden(1, True)


    def removePath(self):
        indexes = self.path_list.selectionModel().selectedRows()
        for index in sorted(indexes):
            path = self.path_list.cellWidget(index.row(), 0).text()
            Type = self.path_list.item(index.row(), 1).text()
            cmd = 'python script\\file_system\\demo_integrity.py -r '+'"'+path+'"' +' '+Type
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
        self.showPathTable()

    def updatePath(self):
        self.showPathTable()

    def showDetailReportIntegrity(self):
        layout = QGridLayout()
        try:
            layout = self.scrollArea_intefrity.findChild(QLayout,"report_integrity_list")
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                  child.widget().deleteLater()
        except Exception as e:
            layout = QGridLayout(self.list_report_integrity)
            layout.setObjectName("report_integrity_list") 
        cmd = 'python script\\file_system\\demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['alert_list']

        i = 0
        for data in data:
            widget = QWidget()
            widget.setStyleSheet("QWidget {background: rgba(255,255,255,0.1); border-radius: 5px;} QLabel{background: transparent;} QWidget:hover {background: rgba(255,255,255,0.2);} QLabel:hover {background: transparent}")
            widget.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            widget.setObjectName(str(i)+"||widget_report")
            widget.setFixedHeight(65)
            name = QLabel(data[3])
            name.setObjectName(str(i)+"||label_name_report")
            status = QLabel(data[2])
            status.setObjectName(str(i)+"||label_status_report")
            status.setStyleSheet("QLabel {color: #72ac57}")
            timeReport = QLabel(data[1])
            timeReport.setObjectName(str(i)+"||label_time_report")
            timeReport.setAlignment(Qt.AlignCenter | Qt.AlignRight);
            
            layoutItem = QGridLayout(widget)
            layoutItem.addWidget(name, 0, 0)
            layoutItem.addWidget(timeReport, 0, 1)
            layoutItem.addWidget(status, 1, 0)
            layout.addWidget(widget, i, 0)
            i=i+1
            if(i == 100):
                break


    def reportScan(self):
        cmd = 'python script\\file_system\\demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['alert_list']
        i = 0
        for data in data:
            if(i == 0):
                self.path_integrity_1.setText(data[3])
                self.status_integrity_1.setText(data[2])
                self.status_integrity_1.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_1.setText(data[1])
            elif( i == 1):
                self.path_integrity_2.setText(data[3])
                self.status_integrity_2.setText(data[2])
                self.status_integrity_2.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_2.setText(data[1])
            else:
                self.path_integrity_3.setText(data[3])
                self.status_integrity_3.setText(data[2])
                self.status_integrity_3.setStyleSheet("QLabel {color: #72ac57}")
                self.time_report_integrity_3.setText(data[1])
            i = i + 1
            if(i == 3):
                break




    # =============================================Giám sát tệp tin, thư mục ================================================================#

    def addFileMonitor(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            self.path_file_monitor.setText(fileName)
            cmd = 'python script\\file_system\\demo_monitor.py -i ' + '"'+fileName+'"' +' 0'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTableMonitor()



    def addFolderMonitor(self, instance):
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory","/home",QFileDialog.ShowDirsOnly|QFileDialog.DontResolveSymlinks)
        if folderName:
            self.path_folder.setText(folderName)
            cmd = 'python script\\file_system\\demo_monitor.py -i ' + '"'+folderName+'"' +' 1'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            if(p_status == 0):
                self.showPathTableMonitor()


    def showPathTableMonitor(self):
        cmd = 'python script\\file_system\\demo_monitor.py -l'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = json.loads(output.decode('ASCII'))['check_list']
        if(p_status == 0):
            self.path_list_monitor.setColumnCount(2)
            self.path_list_monitor.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[2])
                self.path_list_monitor.setCellWidget(i,0,path)
                self.path_list_monitor.setItem(i, 1, QTableWidgetItem(str(data[1])))
                i = i + 1
            self.path_list_monitor.setColumnHidden(1, True)


    def removePathMonitor(self):
        indexes = self.path_list_monitor.selectionModel().selectedRows()
        for index in sorted(indexes):
            path = self.path_list_monitor.cellWidget(index.row(), 0).text()
            Type = self.path_list_monitor.item(index.row(), 1).text()
            cmd = 'python script\\file_system\\demo_monitor.py -r '+'"'+path+'"' +' '+Type
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
        self.showPathTableMonitor()


    def updatePathMonitor(self):
        self.showPathTableMonitor()
        self.reportScanMonitor()
        self.update_file_monitor.setText("Cập nhật")


    def reportScanMonitor(self):
        cmd = 'python script\\file_system\\demo_monitor.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.report_table.setColumnCount(5)
            self.report_table.setRowCount(len(data))
            i = 0
            for data in data:
                self.report_table.setItem(i, 0, QTableWidgetItem(data[1]))
                self.report_table.setItem(i, 1, QTableWidgetItem(data[2]))
                self.report_table.setItem(i, 2, QTableWidgetItem(data[3]))
                self.report_table.setItem(i, 3, QTableWidgetItem(data[4]))
                self.report_table.setItem(i, 4, QTableWidgetItem(data[5]))
                self.report_table.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                i = i + 1
                if(i == 100):
                    break
        except Exception as e:
            print(e)



            


    ############################################### End file system protection #######################################################


    ############################################### Quét mã độc #######################################################

    #============================================= quick scan =========================================================

    def quickScanStart(self, instance):
        self.info_quick_scan.setVisible(True)
        self.quick_scan_stop.setVisible(True)

        global isStopQuickScan
        if(isStopQuickScan == 1):
            isStopQuickScan = 0
            self.quick_scan_start.setEnabled(False)
            self.quick_scan_stop.setEnabled(True)
            return

        isStopQuickScan = 0
        self.quick_scan_start.setEnabled(False)
        self.quick_scan_stop.setEnabled(True)
        global listVirusQuickScan
        listVirusQuickScan = []

        self.progressBar_quickScan.setMaximum(100)
        self.progressBar_quickScan.setValue(0)
        self.mess_quick_scan.setText("0")
        self.fileQuickScaned.setText("0")
        self.path_quick_scan.setText("Đang kiểm tra... ")
        self.path_quick_scan.setIcon(QtGui.QIcon())

        runThreadProcessBarQuickScan = processBarQuickScan(self)
        runThreadProcessBarQuickScan.endQuickScanVisible.connect(self.visibleEndQuickScan)
        runThreadProcessBarQuickScan.updateVirus.connect(self.mess_quick_scan.setText)
        runThreadProcessBarQuickScan.updateIndex.connect(self.fileQuickScaned.setText)
        runThreadProcessBarQuickScan.updatePath.connect(self.path_quick_scan_name.setText)
        runThreadProcessBarQuickScan.updateProcessBar.connect(self.progressBar_quickScan.setValue)
        runThreadProcessBarQuickScan.completeScan.connect(self.completeQuickScan)
        runThreadProcessBarQuickScan.start()


    def completeQuickScan(self):
        self.path_quick_scan.setIcon(QtGui.QIcon("icon/check.png"))
        self.progressBar_quickScan.setValue(100)
        self.path_quick_scan.setText("Đã quét xong")
        self.path_quick_scan_name.setText("")
        self.quick_scan_start.setEnabled(True)
        self.quick_scan_stop.setEnabled(False)
        self.quick_scan_end.setVisible(False)
        self.quick_scan_end.setEnabled(False)

    def visibleEndQuickScan(self):
        self.quick_scan_end.setVisible(True)
        self.quick_scan_end.setEnabled(True)


    def quickScanStop(self, instance):
        self.quick_scan_start.setEnabled(True)
        self.quick_scan_stop.setEnabled(False)
        global isStopQuickScan
        isStopQuickScan = 1;


    def quickScanEnd(self, instance):
        self.quick_scan_start.setEnabled(False)
        self.quick_scan_stop.setEnabled(False)
        self.quick_scan_end.setEnabled(False)
        global isStopQuickScan
        isStopQuickScan = 2;

    #============================================= full scan =========================================================

    def fullScanStart(self, instance):
        self.info_full_scan.setVisible(True)
        self.full_scan_stop.setVisible(True)
        
        global isStopFullScan
        if(isStopFullScan == 1):
            isStopFullScan = 0
            self.full_scan_start.setEnabled(False)
            self.full_scan_stop.setEnabled(True)
            return

        isStopFullScan = 0
        self.full_scan_start.setEnabled(False)
        self.full_scan_stop.setEnabled(True)
        global listVirusFullScan
        listVirusFullScan = []

        self.progressBar_fullScan.setMaximum(100)
        self.progressBar_fullScan.setValue(0)
        self.mess_full_scan.setText("0")
        self.fileScaned.setText("0")
        self.path_full_scan.setText("Đang kiểm tra... ")
        self.path_full_scan.setIcon(QtGui.QIcon())

        runThreadProcessBarFullScan = processBarFullScan(self)
        runThreadProcessBarFullScan.endFullScanVisible.connect(self.visibleEndFullScan)
        runThreadProcessBarFullScan.updateVirus.connect(self.mess_full_scan.setText)
        runThreadProcessBarFullScan.updateIndex.connect(self.fileScaned.setText)
        runThreadProcessBarFullScan.updatePath.connect(self.path_full_scan_name.setText)
        runThreadProcessBarFullScan.updateProcessBar.connect(self.progressBar_fullScan.setValue)
        runThreadProcessBarFullScan.completeScan.connect(self.completeFullScan)
        runThreadProcessBarFullScan.start()


    def completeFullScan(self):
        self.path_full_scan.setIcon(QtGui.QIcon("icon/check.png"))
        self.progressBar_fullScan.setValue(100)
        self.path_full_scan.setText("Đã quét xong")
        self.path_full_scan_name.setText("")
        self.full_scan_start.setEnabled(True)
        self.full_scan_stop.setEnabled(False)
        self.full_scan_end.setVisible(False)
        self.full_scan_end.setEnabled(False)

    def visibleEndFullScan(self):
        self.full_scan_end.setVisible(True)
        self.full_scan_end.setEnabled(True)


    def fullScanStop(self, instance):
        self.full_scan_start.setEnabled(True)
        self.full_scan_stop.setEnabled(False)
        global isStopFullScan
        isStopFullScan = 1;


    def fullScanEnd(self, instance):
        self.full_scan_start.setEnabled(False)
        self.full_scan_stop.setEnabled(False)
        self.full_scan_end.setEnabled(False)
        global isStopFullScan
        isStopFullScan = 2;


    #============================================== selective scan ====================================================#

    def showPathScan(self):
        self.restore_list_path.setVisible(True)
        self.add_folder_scan_box.hide()
        global listScan
        self.list_file_scan.setColumnCount(1)
        self.list_file_scan.setRowCount(len(listScan))
        i = 0
        for data in listScan:
            path = QPushButton()
            path.setIcon(QtGui.QIcon("icon/file-1294459_1280.png"))
            path.setStyleSheet("QPushButton {text-align: left; padding-left: 5px;}");
            path.setText(data[0])
            self.list_file_scan.setCellWidget(i,0,path)
            i = i + 1

    def restoreListPath(self,instance):
        global listScan
        listScan = []
        self.showPathScan()




    def addFileScan(self, instance):
        fileName, _ = QFileDialog.getOpenFileName(self,'Open file','/home','All files (*.*)',options=QFileDialog.DontUseNativeDialog)
        if fileName:
            global listScan
            listScan.append([fileName,0])
            self.showPathScan()

            # cmd = 'python script\\file_system\\demo_integrity.py -i ' + '"'+fileName+'"' +' 0'
            # p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            # (output, err) = p.communicate()
            # p_status = p.wait()
            # if(p_status == 0):
            #     self.showPathTable()

    def addFolderScan(self, instance):
        option = QFileDialog.Options()
        folderName = QFileDialog.getExistingDirectory(self, "Open Directory",
                                             "/home",
                                             QFileDialog.ShowDirsOnly
                                             | QFileDialog.DontResolveSymlinks)
        if folderName:
            global listScan
            listScan.append([folderName,1])
            self.showPathScan()



    def selectiveScanStart(self, instance):
        self.widget_scan.setVisible(True)
        self.selective_scan_start.setEnabled(False)
        global listVirusSelectiveScan
        listVirusSelectiveScan = []

        self.progressBar_selective_scan.setMaximum(100)
        self.mess_scan.setText("Tìm thấy 0 tệp độc hại")
        self.path_scan.setText("Đang kiểm tra... ")
        self.path_scan.setIcon(QtGui.QIcon())

        runThreadSelectiveScan = ThreadSelectiveScan(self)
        runThreadSelectiveScan.updateVirus.connect(self.mess_scan.setText)
        runThreadSelectiveScan.updatePath.connect(self.path_scan_name.setText)
        runThreadSelectiveScan.updateProcessBar.connect(self.progressBar_selective_scan.setValue)
        runThreadSelectiveScan.completeScan.connect(self.completeSelectiveScan)
        runThreadSelectiveScan.start()


    def completeSelectiveScan(self):
        self.path_scan.setIcon(QtGui.QIcon("icon/check.png"))
        self.progressBar_selective_scan.setValue(100)
        self.path_scan.setText("Đã quét xong")
        self.path_scan_name.setText("")
        self.selective_scan_start.setEnabled(True)


    #==============================================virus list======================================================#

    def showListVirusScan(self, typeScan):
        files = []
        global isListVirus
        if(typeScan == "full_scan"):
            global listVirusFullScan
            files = listVirusFullScan
            isListVirus = "full_scan"
        elif(typeScan == "quick_scan"):
            global listVirusQuickScan
            files = listVirusQuickScan
            isListVirus = "quick_scan"
        elif(typeScan == "selective_scan"):
            global listVirusSelectiveScan
            files = listVirusSelectiveScan
            isListVirus = "selective_scan"

        self.main.setCurrentIndex(21)
        self.table_virus.setColumnCount(2)
        self.table_virus.setRowCount(len(files))

        i = 0
        for i in range(0,len(files)): 
            path = QPushButton()
            path.setIcon(QtGui.QIcon("icon/bug.png"))
            path.setStyleSheet("QPushButton {text-align: left; padding-left: 5px;}");
            path.setText(files[i]["path"])
            self.table_virus.setCellWidget(i,0,path)
            self.table_virus.setItem(i,1, QTableWidgetItem(files[i]["time"]))


    def removeVirus(self):
        global isListVirus
        indexes = self.table_virus.selectionModel().selectedRows()
        for index in sorted(indexes):
            path = self.table_virus.cellWidget(index.row(), 0).text()
            cmd = 'script\\clamav-0.101.0-win-x64-portable\\clamdscan.exe --remove '+'"'+path+'"'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            state = str(output)
            if((state.find("Infected files: 1") != -1) and (state.find("Removed") != -1)):
                if(isListVirus == "full_scan"):
                    global listVirusFullScan
                    i = 0
                    for virus in listVirusFullScan:
                        if(virus["path"]==path):
                            virus["time"]="Đã xóa"
                        i = i + 1
                elif(isListVirus == "quick_scan"):
                    global listVirusQuickScan
                    i = 0
                    for virus in listVirusQuickScan:
                        if(virus["path"]==path):
                            virus["time"]="Đã xóa"
                        i = i + 1
                elif(isListVirus == "selective_scan"):
                    global listVirusSelectiveScan
                    i = 0
                    for virus in listVirusSelectiveScan:
                        if(virus["path"]==path):
                            virus["time"]="Đã xóa"
                        i = i + 1

        self.showListVirusScan(isListVirus)
 



    ############################################### infomation #######################################################

    def confirmDelete(self):
        choice = QMessageBox.question(self, 'Cảnh báo!', "Bạn có chắc chắn muốn xóa?", QMessageBox.No | QMessageBox.Yes)
        if choice == QMessageBox.Yes:
            pass
            return 1
        else:
            pass
            return 0

    def confirmChangeState(self):
        choice = QMessageBox.question(self, 'Cảnh báo!', "Bạn có chắc chắn muốn thay đổi?", QMessageBox.No | QMessageBox.Yes)
        if choice == QMessageBox.Yes:
            pass
            return 1
        else:
            pass
            return 0


    def netstat(self):
        cmd = 'script\\netstat\\netstat.exe'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        dataStr = output.decode('ASCII')
        dataJson = json.loads(dataStr)

    def updateNetstat(self):
        cmd = 'script\\netstat\\netstat.exe'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        dataStr = output.decode('ASCII')
        dataJson = json.loads(dataStr)
        self.tableNetstat.setColumnCount(8)
        self.tableNetstat.setRowCount(len(dataJson))
        self.tableNetstat.mouseReleaseEvent = self.viewClicked

        for i in range(0,len(dataJson)):
            for key in dataJson[i]:
                if key == "Remote address":
                    if type(dataJson[i][key]) is str:
                        continue
                    else:
                        self.tableNetstat.setItem(i,4, QTableWidgetItem(dataJson[i][key][0]))
                        self.tableNetstat.setItem(i,5, QTableWidgetItem(str(dataJson[i][key][1])))
                elif key == "Proto":
                    self.tableNetstat.setItem(i,2, QTableWidgetItem(dataJson[i][key]))
                elif key == "Status":
                    self.tableNetstat.setItem(i,3, QTableWidgetItem(dataJson[i][key]))
                    if dataJson[i][key] == "LISTEN":
                        self.tableNetstat.item(i, 3).setForeground(QtGui.QColor(70, 178, 66))
                elif key == "Local address":
                    if type(dataJson[i][key]) is str:
                        continue
                    else:
                        self.tableNetstat.setItem(i,6, QTableWidgetItem(dataJson[i][key][0]))
                        self.tableNetstat.setItem(i,7, QTableWidgetItem(str(dataJson[i][key][1])))
                elif key == "Program name":
                    label = QPushButton(self)
                    if dataJson[i][key] == "chrome":
                        label.setIcon(QtGui.QIcon("icon/chrome.png"))
                    else:
                        label.setIcon(QtGui.QIcon("icon/unknow.png"))
                    label.setText(dataJson[i][key])
                    label.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");
                    self.tableNetstat.setCellWidget(i,0,label)
                elif key == "PID": 
                    self.tableNetstat.setItem(i,1, QTableWidgetItem(dataJson[i][key]))



    def viewClicked(self,event):
        indexes = self.tableNetstat.selectionModel().selectedRows()
        row = self.tableNetstat.selectionModel().currentIndex().row()
        column = self.tableNetstat.selectionModel().currentIndex().column()
        # value = self.tableNetstat.item(row, column).text()

        if event.button() == 2:
            for index in sorted(indexes):
                print('Row %d is selected' % index.row())
            # QMessageBox.about(self, "Title", "Message")
            menu = QMenu()
            CutAction = menu.addAction("Kill")
            menu.addAction(CutAction)
            CutAction.setIcon(QtGui.QIcon("icon/close.png"))
            CutAction.setShortcut("Ctrl+K")
            CutAction.triggered.connect(lambda: self.killFirewall(event))
            menu.exec_(event.globalPos())

    def killFirewall(self,event):
        print(event)


    def infoHardDisk(self):
        cmd = "wmic logicaldisk get size,freespace,caption"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = str(output).split("\\n")
        data.pop(0)
        del data[-1]
        del data[-1]

        self.table_disk.setColumnCount(3)
        self.table_disk.setRowCount(len(data))
        for i in range(0,len(data)):
            disk = data[i].split()
            label = QPushButton()
            label.setIcon(QtGui.QIcon("icon/hard_disk.png"))
            label.setIconSize(QtCore.QSize(30, 30)) 
            label.setText(disk[0])
            label.setStyleSheet("QPushButton {background-color: transparent;text-align: left; padding-left: 5px;}");
            self.table_disk.setCellWidget(i,0,label) 

            try:
                value = int((1-(float(disk[1])/float(disk[2])))*100)
            except Exception as e:
                value = 0
            progress = QProgressBar()
            progress.setStyleSheet("QProgressBar {height: 5px;}")
            progress.setMaximum(100)
            progress.setValue(value)
            self.table_disk.setCellWidget(i,1,progress)
            try:
                size = "Total: " + str(int(((float(disk[2])/1024)/1024)/1024)) + " GB"
            except Exception as e:
                size = "Rỗng"
            self.table_disk.setItem(i,2, QTableWidgetItem(size))




    def inforDisk(self):
        cmd ="wmic diskdrive get model,size"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = str(output).split("\\n")
        data.pop(0)
        del data[-1]
        del data[-1]
        index = 1
        for model in data:
            if index == 1:
                self.disk_1.setVisible(True)
                disk = model.split()
                diskSize = disk[-2]
                diskSize = ((float(diskSize)/1024)/1024)/1024
                del disk[-1]
                del disk[-1]
                diskName = ' '.join(disk)
                self.disk_name_01.setText(diskName +"  "+ str(int(diskSize)) + "GB")
                self.scrollArea_disk.resize(691,90);
                index= index + 1
                continue
            if index == 2:
                self.disk_2.setVisible(True)
                disk = model.split()
                diskSize = disk[-2]
                diskSize = ((float(diskSize)/1024)/1024)/1024
                del disk[-1]
                del disk[-1]
                diskName = ' '.join(disk)
                self.disk_name_222.setText(diskName +"  "+ str(int(diskSize)) + "GB")
                self.scrollArea_disk.resize(691,180);
                index= index + 1
                continue
            if index == 3:
                self.disk_3.setVisible(True)
                disk = model.split()
                diskSize = disk[-2]
                diskSize = ((float(diskSize)/1024)/1024)/1024
                del disk[-1]
                del disk[-1]
                diskName = ' '.join(disk)
                self.disk_name_03.setText(diskName +"  "+ str(int(diskSize)) + "GB")
                index= index + 1
                continue
            if index == 4:
                self.disk_4.setVisible(True)
                disk = model.split()
                diskSize = disk[-2]
                diskSize = ((float(diskSize)/1024)/1024)/1024
                del disk[-1]
                del disk[-1]
                diskName = ' '.join(disk)
                self.disk_name_04.setText(diskName +"  "+ str(int(diskSize)) + "GB")
                index= index + 1
                continue


    def netinfo(self):
        self.network.clicked.connect(self.showChartNetwork)
        self.network.clear()

        addr = psutil.net_if_addrs()
        ifaceList  = addr.keys()
        byte = psutil.net_io_counters(pernic=True)

        index = 0
        for iface in ifaceList:
            net = iface
            ip = addr[iface][1][1]
            try:
                ipcheck = ip.split(".")[3]
                status = "UP"
            except:
                status = "Down"

            if(status == "UP"):
                button = QPushButton(self)
                button.setText(status)
                button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px; color: #55aa00;}");
                # QTreeWidgetItem(self.network, [net, ip])
                item = QTreeWidgetItem([net, ip])
                self.network.addTopLevelItem(item)
                self.network.setItemWidget(item, 2, button)
            else:
                button = QPushButton(self)
                button.setText(status)
                button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px; color: red;}");
                # QTreeWidgetItem(self.network, [net, ip])
                item = QTreeWidgetItem([net, ip])
                self.network.addTopLevelItem(item)
                self.network.setItemWidget(item, 2, button)
            runThreadChartNetWork = ThreadChartNetWork(self, net)
            runThreadChartNetWorks.append(runThreadChartNetWork)
            runThreadChartNetWork.start()
            if(index == 0):
                global gcard
                gcard = net
            index = index + 1


        

    def showChartNetwork(self):
        global runThreadChartNetWorks;
        card = self.network.currentItem().text(0)

        for thread in runThreadChartNetWorks:
            if(thread.getCard() == card):
                byte = psutil.net_io_counters(pernic=True)
                in_byte = byte[card][0]
                out_byte = byte[card][1]
                tx = round((in_byte/1024)/1024,2)
                self.card_name.setText(card)
                self.tx.setText(" " + str(tx) + " Mbps") 
                rx = round((out_byte/1024)/1024,2)
                self.card_name.setText(card)
                self.rx.setText(" " + str(rx) + " Mbps")

                X, Y, Y1 = thread.getData()
                self.chart_network.canvas.axes.clear()
                self.chart_network.canvas.figure.set_facecolor("#121416")
                self.chart_network.canvas.axes.patch.set_alpha(0.0)
                self.chart_network.canvas.axes.figure.set_facecolor('None')
                self.chart_network.canvas.axes.tick_params(labelcolor='#c7c7c9')
                self.chart_network.canvas.axes.set_xticklabels([])
                self.chart_network.canvas.axes.plot(X, Y, color='#f07d47')
                self.chart_network.canvas.axes.plot(X, Y1, color='#87ceeb')
                self.chart_network.canvas.axes.fill_between(X, 0, Y, color='#ff9292', alpha=0.2)
                self.chart_network.canvas.axes.fill_between(X, 0, Y1, color='white', alpha=0.1)
                self.chart_network.canvas.draw()
                break
        global gcard
        gcard = card


    def updateInfo(self, time, up_time, process, swap):
        self.time_information.setText(time)
        self.uptime_information.setText(up_time)
        self.process_information.setText(process)
        self.swap_information.setText(swap)



    def getConigHardware(self):
        cmd = '.\powershell\systeminfo.ps1'
        p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
    
        (output, err) = p.communicate()
        p_status = p.wait()
        data = str(output).split("|||")
        self.config_hardware.setColumnCount(4)
        self.config_hardware.setRowCount(len(data)-1)
        check_header = 0
        for i in range(1,len(data)-1):
            for j in range(0,4):
                try:
                    if check_header == 1:
                        test =1
                        # in dam dong
                    if "*****" in data[i]:
                        check_header == 1
                    else:
                        check_header == 0
                    if(j == 0):
                        path = QPushButton()
                        path.setIcon(QtGui.QIcon("icon/folder.png"))
                        path.setStyleSheet("QPushButton {text-align: left;}");
                        path.setText((data[i].split('||')[j]).replace('\\n', '').replace('*****','').replace('|', '').replace('\\r', ''))
                        self.config_hardware.setCellWidget(i-1,j,path)
                    else:
                        self.config_hardware.setItem(i-1,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '').replace('*****','').replace('|', '').replace('\\r', '')))
                except:
                    continue

               

    def getProcessList(self):
        cmd = '.\powershell\process.ps1'
        p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = str(output).split("|||")
        del data[0]
        self.process_list.setColumnCount(5)
        self.process_list.setRowCount(len(data)-1)
        for i in range(0,len(data)-1):
            for j in range(0,5):
                if(j == 0):
                    button = QPushButton(self)
                    if (data[i].split('||')[j]).replace('\\n', '') == "chrome  ":
                        button.setIcon(QtGui.QIcon("icon/chrome.png"))
                    else:
                         button.setIcon(QtGui.QIcon("icon/unknow.png"))
                    button.setText(((data[i].split('||')[j]).replace('\\n', '')).replace("\\r",""))
                    button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");
                    self.process_list.setCellWidget(i,0,button)
                    continue
                elif(j==3):
                    self.process_list.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '')))
                    continue
                elif(j==4):
                    self.process_list.setItem(i,j, QTableWidgetItem(((data[i].split('||')[j]).replace('\\n', '')).replace(" ","")))
                    continue
                else:
                    self.process_list.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '') + " %"))
                    continue


    def killProcess(self):
        indexes = self.process_list.selectionModel().selectedRows()
        for index in sorted(indexes):
            PID = self.process_list.item(index.row(), 4).text()
            cmd = "taskkill /PID "+PID+ " /F"
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(cmd)
                self.getProcessList()
            except:
                print("access denied or process does not exist")
                self.getProcessList()



    def updateProcessListThread(self, data):
        self.process_list.setColumnCount(5)
        self.process_list.setRowCount(len(data)-1)
        for i in range(0,len(data)-1):
            for j in range(0,5):
                if(j == 0):
                    button = QPushButton(self)
                    if (data[i].split('||')[j]).replace('\\n', '') == "chrome  ":
                        button.setIcon(QtGui.QIcon("icon/chrome.png"))
                    else:
                         button.setIcon(QtGui.QIcon("icon/unknow.png"))
                    button.setText(((data[i].split('||')[j]).replace('\\n', '')).replace("\\r",""))
                    button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");
                    self.process_list.setCellWidget(i,0,button)
                    continue
                elif(j==3):
                    self.process_list.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '')))
                    continue
                elif(j==4):
                    self.process_list.setItem(i,j, QTableWidgetItem(((data[i].split('||')[j]).replace('\\n', '')).replace(" ","")))
                    continue
                else:
                    self.process_list.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '') + " %"))
                    continue

        self.process_list_2.setColumnCount(5)
        self.process_list_2.setRowCount(len(data)-1)
        for i in range(0,len(data)-1):
            for j in range(0,5):
                if(j == 0):
                    button = QPushButton(self)
                    if (data[i].split('||')[j]).replace('\\n', '') == "chrome  ":
                        button.setIcon(QtGui.QIcon("icon/chrome.png"))
                    else:
                         button.setIcon(QtGui.QIcon("icon/unknow.png"))
                    button.setText(((data[i].split('||')[j]).replace('\\n', '')).replace("\\r",""))
                    button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");
                    self.process_list_2.setCellWidget(i,0,button)
                    continue
                elif(j==3):
                    self.process_list_2.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '')))
                    continue
                elif(j==4):
                    self.process_list_2.setItem(i,j, QTableWidgetItem(((data[i].split('||')[j]).replace('\\n', '')).replace(" ","")))
                    continue
                else:
                    self.process_list_2.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '') + " %"))
                    continue



    def confirmExit(self):
        choice = QMessageBox.question(self, 'Extract!', "Get into the chopper?", QMessageBox.No | QMessageBox.Yes)
        if choice == QMessageBox.Yes:
            print("Exit")
            global check_thread_chart_network
            check_thread_chart_network = 0
            sys.exit()
        else:
            pass

    def showIncomingTraffic(self):
        cmd = 'script\\firewall\\window_firewall.exe -L'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = output.decode('ASCII')
        data = json.loads(data)
        RuleIn = []
        for data in data:
            try:
                if(data['Direction'] == "In"):
                    RuleIn.append(data)
            except:
                continue

        self.incoming_traffic.setColumnCount(12)
        self.incoming_traffic.setRowCount(len(RuleIn))
        self.incoming_traffic.clicked.connect(self.showDetailRuleIn)
        i = 0
        for rule in RuleIn:
            try:
                self.incoming_traffic.setItem(i,0, QTableWidgetItem(rule['Rule Name']))
            except:
                self.incoming_traffic.setItem(i,0, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,1, QTableWidgetItem(rule['Profiles']))
            except:
                self.incoming_traffic.setItem(i,1, QTableWidgetItem('Unknown'))
            try:
                if(rule['Enabled'] == "Yes"):
                    self.incoming_traffic.setItem(i,2, QTableWidgetItem("Hoạt động"))
                    self.incoming_traffic.item(i,2).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.incoming_traffic.setItem(i,2, QTableWidgetItem("Tắt"))
                    self.incoming_traffic.item(i,2).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.incoming_traffic.setItem(i,2, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,3, QTableWidgetItem(rule['Direction']))
            except:
                self.incoming_traffic.setItem(i,3, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,4, QTableWidgetItem(rule['Grouping']))
            except:
                self.incoming_traffic.setItem(i,4, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,5, QTableWidgetItem(rule['LocalIP']))
            except:
                self.incoming_traffic.setItem(i,5, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,6, QTableWidgetItem(rule['RemoteIP']))
            except:
                self.incoming_traffic.setItem(i,6, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,7, QTableWidgetItem(rule['Protocol']))
            except:
                self.incoming_traffic.setItem(i,7, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,8, QTableWidgetItem(rule['LocalPort']))
            except:
                self.incoming_traffic.setItem(i,8, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,9, QTableWidgetItem(rule['RemotePort']))
            except:
                self.incoming_traffic.setItem(i,9, QTableWidgetItem('Unknown'))
            try:
                self.incoming_traffic.setItem(i,10, QTableWidgetItem(rule['Edge traversal']))
            except:
                self.incoming_traffic.setItem(i,10, QTableWidgetItem('Unknown'))
            try:
                if(rule['Action'] == "Allow"):
                    self.incoming_traffic.setItem(i,11, QTableWidgetItem("Cho phép"))
                    self.incoming_traffic.item(i,11).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.incoming_traffic.setItem(i,11, QTableWidgetItem("Chặn"))
                    self.incoming_traffic.item(i,11).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.incoming_traffic.setItem(i,11, QTableWidgetItem('Unknown'))
            i = i + 1
        self.remove_rule.setEnabled(False)

    def showDetailRuleIn(self):
        self.remove_rule.setEnabled(True)
        indexes = self.incoming_traffic.selectionModel().selectedRows()
        index = sorted(indexes)[0]

        ruleName = self.incoming_traffic.item(index.row(), 0).text()
        profiles = self.incoming_traffic.item(index.row(), 1).text()
        enabled = self.incoming_traffic.item(index.row(), 2).text()
        direction = self.incoming_traffic.item(index.row(), 3).text()
        grouping = self.incoming_traffic.item(index.row(), 4).text()
        localIP = self.incoming_traffic.item(index.row(), 5).text()
        remoteIP = self.incoming_traffic.item(index.row(), 6).text()
        protocol = self.incoming_traffic.item(index.row(), 7).text()
        localPort = self.incoming_traffic.item(index.row(), 8).text()
        remotePort = self.incoming_traffic.item(index.row(), 9).text()
        edgeTraversal = self.incoming_traffic.item(index.row(), 10).text()

        self.ruleName.setText(ruleName)
        myFont=QtGui.QFont()
        myFont.setBold(True)
        self.ruleName.setFont(myFont)
        self.profiles.setText(profiles)
        self.enabled.setText(enabled)
        self.direction.setText(direction)
        self.grouping.setText(grouping)
        self.localIP.setText(localIP)
        self.remoteIP.setText(remoteIP)
        self.rule_protocol.setText(protocol)
        self.localPort.setText(localPort)
        self.remotePort.setText(remotePort)
        self.edgeTraversal.setText(edgeTraversal)


    def removeRuleIn(self,instance):
        confirm = self.confirmDelete()
        if confirm == 0:
            return
        indexes = self.incoming_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            ruleName = self.incoming_traffic.item(index.row(), 0).text()
            cmd = 'script\\firewall\\window_firewall.exe -D -n '+ruleName
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            print(output)
        self.showIncomingTraffic()



    def changeStateInRule(self,instance):
        confirm = self.confirmChangeState()
        if confirm == 0:
            return
        indexes = self.incoming_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            try:
                Enabled = self.incoming_traffic.item(index.row(), 2).text()
                if(Enabled == "Hoạt động"):
                    action = "--disable-rule"
                else:
                    action = "--enable-rule"
                ruleName = self.incoming_traffic.item(index.row(), 0).text()
                cmd = 'script\\firewall\\window_firewall.exe '+ action +' -n '+ruleName
                print(cmd)
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(output)
            except Exception as e:
                print(e)
        self.showIncomingTraffic()



    def showOutTraffic(self):
        cmd = 'script\\firewall\\window_firewall.exe -L'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = output.decode('ASCII')
        data = json.loads(data)
        RuleOut = []
        for data in data:
            try:
                if(data['Direction'] == "Out"):
                    RuleOut.append(data)
            except:
                continue
        self.out_traffic.setColumnCount(12)
        self.out_traffic.setRowCount(len(RuleOut))
        self.out_traffic.clicked.connect(self.showDetailRuleOut)
        i = 0
        for rule in RuleOut:
            try:
                self.out_traffic.setItem(i,0, QTableWidgetItem(rule['Rule Name']))
            except:
                self.out_traffic.setItem(i,0, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,1, QTableWidgetItem(rule['Profiles']))
            except:
                self.out_traffic.setItem(i,1, QTableWidgetItem('Unknown'))
            try:
                if(rule['Enabled'] == "Yes"):
                    self.out_traffic.setItem(i,2, QTableWidgetItem("Hoạt động"))
                    self.out_traffic.item(i,2).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.out_traffic.setItem(i,2, QTableWidgetItem("Tắt"))
                    self.out_traffic.item(i,2).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.out_traffic.setItem(i,2, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,3, QTableWidgetItem(rule['Direction']))
            except:
                self.out_traffic.setItem(i,3, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,4, QTableWidgetItem(rule['Grouping']))
            except:
                self.out_traffic.setItem(i,4, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,5, QTableWidgetItem(rule['LocalIP']))
            except:
                self.out_traffic.setItem(i,5, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,6, QTableWidgetItem(rule['RemoteIP']))
            except:
                self.out_traffic.setItem(i,6, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,7, QTableWidgetItem(rule['Protocol']))
            except:
                self.out_traffic.setItem(i,7, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,8, QTableWidgetItem(rule['LocalPort']))
            except:
                self.out_traffic.setItem(i,8, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,9, QTableWidgetItem(rule['RemotePort']))
            except:
                self.out_traffic.setItem(i,9, QTableWidgetItem('Unknown'))
            try:
                self.out_traffic.setItem(i,10, QTableWidgetItem(rule['Edge traversal']))
            except:
                self.out_traffic.setItem(i,10, QTableWidgetItem('Unknown'))
            try:
                if(rule['Action'] == "Allow"):
                    self.out_traffic.setItem(i,11, QTableWidgetItem("Cho phép"))
                    self.out_traffic.item(i,11).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.out_traffic.setItem(i,11, QTableWidgetItem("Chặn"))
                    self.out_traffic.item(i,11).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.out_traffic.setItem(i,11, QTableWidgetItem('Unknown'))
            i = i + 1
        self.remove_rule_out.setEnabled(False)


    def showDetailRuleOut(self):
        self.remove_rule_out.setEnabled(True)
        indexes = self.out_traffic.selectionModel().selectedRows()
        index = sorted(indexes)[0]

        ruleName = self.out_traffic.item(index.row(), 0).text()
        profiles = self.out_traffic.item(index.row(), 1).text()
        enabled = self.out_traffic.item(index.row(), 2).text()
        direction = self.out_traffic.item(index.row(), 3).text()
        grouping = self.out_traffic.item(index.row(), 4).text()
        localIP = self.out_traffic.item(index.row(), 5).text()
        remoteIP = self.out_traffic.item(index.row(), 6).text()
        protocol = self.out_traffic.item(index.row(), 7).text()
        localPort = self.out_traffic.item(index.row(), 8).text()
        remotePort = self.out_traffic.item(index.row(), 9).text()
        edgeTraversal = self.out_traffic.item(index.row(), 10).text()

        self.ruleName_2.setText(ruleName)
        myFont=QtGui.QFont()
        myFont.setBold(True)
        self.ruleName_2.setFont(myFont)
        self.profiles_2.setText(profiles)
        self.enabled_2.setText(enabled)
        self.direction_2.setText(direction)
        self.grouping_2.setText(grouping)
        self.localIP_2.setText(localIP)
        self.remoteIP_2.setText(remoteIP)
        self.rule_protocol_2.setText(protocol)
        self.localPort_2.setText(localPort)
        self.remotePort_2.setText(remotePort)
        self.edgeTraversal_2.setText(edgeTraversal)


    def removeRuleOut(self,instance):
        confirm = self.confirmDelete()
        if confirm == 0:
            return
        indexes = self.out_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            ruleName = self.out_traffic.item(index.row(), 0).text()
            cmd = 'script\\firewall\\window_firewall.exe -D -n '+ruleName
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            print(output)
        self.showOutTraffic()


    def changeStateOutRule(self,instance):
        confirm = self.confirmChangeState()
        if confirm == 0:
            return
        indexes = self.out_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            try:
                Enabled = self.out_traffic.item(index.row(), 2).text()
                if(Enabled == "Hoạt động"):
                    action = "--disable-rule"
                else:
                    action = "--enable-rule"
                ruleName = self.out_traffic.item(index.row(), 0).text()
                cmd = 'script\\firewall\\window_firewall.exe '+ action +' -n '+ruleName
                print(cmd)
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(output)
            except Exception as e:
                print(e)
        self.showOutTraffic()


    def showProgramTraffic(self):
        cmd = 'script\\firewall\\window_firewall.exe -L'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = output.decode('ASCII')
        data = json.loads(data)
        RuleProgram = []
        for data in data:
            try:
                if(data['Program']):
                    RuleProgram.append(data)
            except:
                continue
        self.program_traffic.setColumnCount(12)
        self.program_traffic.setRowCount(len(RuleProgram))
        self.program_traffic.clicked.connect(self.showDetailProgramTraffic)
        i = 0
        for rule in RuleProgram:
            try:
                self.program_traffic.setItem(i,0, QTableWidgetItem(rule['Rule Name']))
            except:
                self.program_traffic.setItem(i,0, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,1, QTableWidgetItem(rule['Profiles']))
            except:
                self.program_traffic.setItem(i,1, QTableWidgetItem('Unknown'))
            try:
                if(rule['Enabled'] == "Yes"):
                    self.program_traffic.setItem(i,2, QTableWidgetItem("Hoạt động"))
                    self.program_traffic.item(i,2).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.program_traffic.setItem(i,2, QTableWidgetItem("Tắt"))
                    self.program_traffic.item(i,2).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.program_traffic.setItem(i,2, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,3, QTableWidgetItem(rule['Direction']))
            except:
                self.program_traffic.setItem(i,3, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,4, QTableWidgetItem(rule['Grouping']))
            except:
                self.program_traffic.setItem(i,4, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,5, QTableWidgetItem(rule['LocalIP']))
            except:
                self.program_traffic.setItem(i,5, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,6, QTableWidgetItem(rule['RemoteIP']))
            except:
                self.program_traffic.setItem(i,6, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,7, QTableWidgetItem(rule['Protocol']))
            except:
                self.program_traffic.setItem(i,7, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,8, QTableWidgetItem(rule['LocalPort']))
            except:
                self.program_traffic.setItem(i,8, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,9, QTableWidgetItem(rule['RemotePort']))
            except:
                self.program_traffic.setItem(i,9, QTableWidgetItem('Unknown'))
            try:
                self.program_traffic.setItem(i,10, QTableWidgetItem(rule['Edge traversal']))
            except:
                self.program_traffic.setItem(i,10, QTableWidgetItem('Unknown'))
            try:
                if(rule['Action'] == "Allow"):
                    self.program_traffic.setItem(i,11, QTableWidgetItem("Cho phép"))
                    self.program_traffic.item(i,11).setForeground(QtGui.QColor(124, 204, 91))
                else:
                    self.program_traffic.setItem(i,11, QTableWidgetItem("Chặn"))
                    self.program_traffic.item(i,11).setForeground(QtGui.QColor(255, 52, 52))
            except:
                self.program_traffic.setItem(i,11, QTableWidgetItem('Unknown'))
            i = i + 1
        self.remove_rule_program.setEnabled(False)

    def showDetailProgramTraffic(self):
        self.remove_rule_program.setEnabled(True)
        indexes = self.program_traffic.selectionModel().selectedRows()
        index = sorted(indexes)[0]

        ruleName = self.program_traffic.item(index.row(), 0).text()
        profiles = self.program_traffic.item(index.row(), 1).text()
        enabled = self.program_traffic.item(index.row(), 2).text()
        direction = self.program_traffic.item(index.row(), 3).text()
        grouping = self.program_traffic.item(index.row(), 4).text()
        localIP = self.program_traffic.item(index.row(), 5).text()
        remoteIP = self.program_traffic.item(index.row(), 6).text()
        protocol = self.program_traffic.item(index.row(), 7).text()
        localPort = self.program_traffic.item(index.row(), 8).text()
        remotePort = self.program_traffic.item(index.row(), 9).text()
        edgeTraversal = self.program_traffic.item(index.row(), 10).text()

        self.ruleName_3.setText(ruleName)
        myFont=QtGui.QFont()
        myFont.setBold(True)
        self.ruleName_3.setFont(myFont)
        self.profiles_3.setText(profiles)
        self.enabled_3.setText(enabled)
        self.direction_3.setText(direction)
        self.grouping_3.setText(grouping)
        self.localIP_3.setText(localIP)
        self.remoteIP_3.setText(remoteIP)
        self.rule_protocol_3.setText(protocol)
        self.localPort_3.setText(localPort)
        self.remotePort_3.setText(remotePort)
        self.edgeTraversal_3.setText(edgeTraversal)


    def removeRuleProgram(self,instance):
        confirm = self.confirmDelete()
        if confirm == 0:
            return
        indexes = self.program_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            ruleName = self.program_traffic.item(index.row(), 0).text()
            cmd = 'script\\firewall\\window_firewall.exe -D -n '+ruleName
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            print(output)
        self.showProgramTraffic()


    def changeStateProgramRule(self,instance):
        confirm = self.confirmChangeState()
        if confirm == 0:
            return
        indexes = self.program_traffic.selectionModel().selectedRows()
        for index in sorted(indexes):
            try:
                Enabled = self.program_traffic.item(index.row(), 2).text()
                if(Enabled == "Hoạt động"):
                    action = "--disable-rule"
                else:
                    action = "--enable-rule"
                ruleName = self.program_traffic.item(index.row(), 0).text()
                cmd = 'script\\firewall\\window_firewall.exe '+ action +' -n '+ruleName
                print(cmd)
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(output)
            except Exception as e:
                print(e)
        self.showOutTraffic()


    def hideColumnsRule(self):
        self.incoming_traffic.setColumnWidth(0, 350)
        self.incoming_traffic.setColumnHidden(1, True)
        self.incoming_traffic.setColumnHidden(7, True)
        self.incoming_traffic.setColumnHidden(3, True)
        self.incoming_traffic.setColumnHidden(4, True)
        self.incoming_traffic.setColumnHidden(5, True)
        self.incoming_traffic.setColumnHidden(6, True)
        self.incoming_traffic.setColumnHidden(8, True)
        self.incoming_traffic.setColumnHidden(9, True)
        self.incoming_traffic.setColumnHidden(10, True)
        self.out_traffic.setColumnWidth(0, 350)
        self.out_traffic.setColumnHidden(1, True)
        self.out_traffic.setColumnHidden(7, True)
        self.out_traffic.setColumnHidden(3, True)
        self.out_traffic.setColumnHidden(4, True)
        self.out_traffic.setColumnHidden(5, True)
        self.out_traffic.setColumnHidden(6, True)
        self.out_traffic.setColumnHidden(8, True)
        self.out_traffic.setColumnHidden(9, True)
        self.out_traffic.setColumnHidden(10, True)
        self.program_traffic.setColumnWidth(0, 350)
        self.program_traffic.setColumnHidden(1, True)
        self.program_traffic.setColumnHidden(7, True)
        self.program_traffic.setColumnHidden(3, True)
        self.program_traffic.setColumnHidden(4, True)
        self.program_traffic.setColumnHidden(5, True)
        self.program_traffic.setColumnHidden(6, True)
        self.program_traffic.setColumnHidden(8, True)
        self.program_traffic.setColumnHidden(9, True)
        self.program_traffic.setColumnHidden(10, True)




    def clearDataInputInRule(self):
        self.source_ip.setText("")
        self.source_port.setText("")
        self.destinationip_ip.setText("")
        self.destinationip_port.setText("")
        self.add_rule_in_name.setText("")
        self.error_add_rule.setText("")

    def clearDataInputOutRule(self):
        self.source_ip_2.setText("")
        self.source_port_2.setText("")
        self.destinationip_ip_2.setText("")
        self.destinationip_port_2.setText("")
        self.add_rule_out_name.setText("")
        self.error_add_rule_2.setText("")

    def clearDataProgramRule(self):
        self.source_ip_3.setText("")
        self.source_port_3.setText("")
        self.destinationip_ip_3.setText("")
        self.destinationip_port_3.setText("")
        self.add_rule_program_name.setText("")
        self.error_add_rule_3.setText("")


    def createNewInRule(self):
        name_rule = self.add_rule_in_name.text()
        protocol = str(self.protocol.currentText())
        source_ip = self.source_ip.text()
        destinationip_ip = self.destinationip_ip.text()
        source_port = self.source_port.text()
        destinationip_port = self.destinationip_port.text()
        cmd_src_ip = ""
        cmd_dst_ip = ""
        cmd_src_port = ""
        cmd_dst_port = ""
        state_rule = " --disable-rule"
        action = " --rule-target block"
        self.error_add_rule.setStyleSheet("QLabel{color: orange;}")

        if(name_rule == ""):
            self.error_add_rule.setText("Không đúng định dạng IP nguồn")
            return 
        name_rule = name_rule.replace(" ","_")

        if(source_ip != ""):
            if len(source_ip.split(".")) != 4:
                self.error_add_rule.setText("Không đúng định dạng IP nguồn")
                return
            else:
                for i in range(0,4):
                    if source_ip.split(".")[i].isnumeric() is False:
                        self.error_add_rule.setText("Không đúng định dạng IP nguồn")
                        return 
            cmd_src_ip = " --src-ip "+source_ip


        if(source_port != ""):
            if source_port.isnumeric() is False:
                self.error_add_rule.setText("Không đúng định dạng cổng nguồn")
                return
            cmd_src_port = " --src-port "+source_port

        
        if(destinationip_ip != ""):
            if len(destinationip_ip.split(".")) != 4:
                self.error_add_rule.setText("Không đúng định dạng IP đích")
                return
            else:
                for i in range(0,4):
                    if destinationip_ip.split(".")[i].isnumeric() is False:
                        self.error_add_rule.setText("Không đúng định dạng IP nguồn")
                        return
            cmd_dst_ip = " --dst-ip "+destinationip_ip


        if(destinationip_port != ""):
            if destinationip_port.isnumeric() is False:
                self.error_add_rule.setText("Không đúng định dạng cổng đích")
                return
            cmd_dst_port = " --dst-port "+destinationip_port


        if (protocol == "icmpv4") or (protocol == "icmpv6") or (protocol == "any"):
            cmd_src_port = ""
            cmd_dst_port = ""



        if self.status.isChecked():
            state_rule = " --enable-rule"
        if self.action.isChecked():
            action = " --rule-target allow"



        cmd = 'script\\firewall\\window_firewall.exe -A --protocol ' + protocol + cmd_src_ip + cmd_dst_ip + cmd_src_port + cmd_dst_port + ' --direction in' + state_rule + action + " --rule-name "+'"'+name_rule+'"'
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        mess = output.decode('ASCII')
        print(mess)
        if(mess.find(""""stdout": "b'Ok""") == -1):
            self.error_add_rule.setText("Thông tin không hợp lệ")
            return

        self.showIncomingTraffic()
        self.main.setCurrentIndex(17)
        



    def createNewOutRule(self):
        name_rule_2 = self.add_rule_out_name.text()
        protocol_2 = str(self.protocol_2.currentText())
        source_ip_2 = self.source_ip_2.text()
        destinationip_ip_2 = self.destinationip_ip_2.text()
        source_port_2 = self.source_port_2.text()
        destinationip_port_2 = self.destinationip_port_2.text()
        cmd_src_ip_2 = ""
        cmd_dst_ip_2 = ""
        cmd_src_port_2 = ""
        cmd_dst_port_2 = ""
        state_rule_2 = " --disable-rule"
        action_2 = " --rule-target block"
        self.error_add_rule_2.setStyleSheet("QLabel{color: orange;}")

        if(name_rule_2 == ""):
            self.error_add_rule_2.setText("Không đúng định dạng IP nguồn")
            return 
        name_rule_2 = name_rule_2.replace(" ","_")

        if(source_ip_2 != ""):
            if len(source_ip_2.split(".")) != 4:
                self.error_add_rule_2.setText("Không đúng định dạng IP nguồn")
                return
            else:
                for i in range(0,4):
                    if source_ip_2.split(".")[i].isnumeric() is False:
                        self.error_add_rule_2.setText("Không đúng định dạng IP nguồn")
                        return 
            cmd_src_ip_2 = " --src-ip "+source_ip_2


        if(source_port_2 != ""):
            if source_port_2.isnumeric() is False:
                self.error_add_rule_2.setText("Không đúng định dạng cổng nguồn")
                return
            cmd_src_port_2 = " --src-port "+source_port_2

        
        if(destinationip_ip_2 != ""):
            if len(destinationip_ip_2.split(".")) != 4:
                self.error_add_rule_2.setText("Không đúng định dạng IP đích")
                return
            else:
                for i in range(0,4):
                    if destinationip_ip_2.split(".")[i].isnumeric() is False:
                        self.error_add_rule_2.setText("Không đúng định dạng IP nguồn")
                        return
            cmd_dst_ip_2 = " --dst-ip "+destinationip_ip_2


        if(destinationip_port_2 != ""):
            if destinationip_port_2.isnumeric() is False:
                self.error_add_rule_2.setText("Không đúng định dạng cổng đích")
                return
            cmd_dst_port_2 = " --dst-port "+destinationip_port_2


        if (protocol_2 == "icmpv4") or (protocol_2 == "icmpv6") or (protocol_2 == "any"):
            cmd_src_port_2 = ""
            cmd_dst_port_2 = ""

        if self.status_2.isChecked():
            state_rule_2 = " --enable-rule"
        if self.action_2.isChecked():
            action_2 = " --rule-target allow"

        cmd = 'script\\firewall\\window_firewall.exe -A --protocol ' + protocol_2 + cmd_src_ip_2 + cmd_dst_ip_2 + cmd_src_port_2 + cmd_dst_port_2 + ' --direction out' + state_rule_2 + action_2 + " --rule-name "+'"'+name_rule_2+'"'
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        mess = output.decode('ASCII')
        print(mess)
        if(mess.find(""""stdout": "b'Ok""") == -1):
            self.error_add_rule_2.setText("Thông tin không hợp lệ")
            return
        
        self.showOutTraffic()
        self.main.setCurrentIndex(18)



    def createNewProgramRule(self):
        name_rule_3 = self.add_rule_program_name.text()
        protocol_3 = str(self.protocol_3.currentText())
        source_ip_3 = self.source_ip_3.text()
        destinationip_ip_3 = self.destinationip_ip_3.text()
        source_port_3 = self.source_port_3.text()
        destinationip_port_3 = self.destinationip_port_3.text()
        cmd_src_ip_3 = ""
        cmd_dst_ip_3 = ""
        cmd_src_port_3 = ""
        cmd_dst_port_3 = ""
        state_rule_3 = " --disable-rule"
        action_3 = " --rule-target block"
        self.error_add_rule_3.setStyleSheet("QLabel{color: orange;}")

        if(name_rule_3 == ""):
            self.error_add_rule_3.setText("Không đúng định dạng IP nguồn")
            return 
        name_rule_3 = name_rule_3.replace(" ","_")

        if(source_ip_3 != ""):
            if len(source_ip_3.split(".")) != 4:
                self.error_add_rule_3.setText("Không đúng định dạng IP nguồn")
                return
            else:
                for i in range(0,4):
                    if source_ip_3.split(".")[i].isnumeric() is False:
                        self.error_add_rule_3.setText("Không đúng định dạng IP nguồn")
                        return 
            cmd_src_ip_3 = " --src-ip "+source_ip_3


        if(source_port_3 != ""):
            if source_port_3.isnumeric() is False:
                self.error_add_rule_3.setText("Không đúng định dạng cổng nguồn")
                return
            cmd_src_port_3 = " --src-port "+source_port_3

        
        if(destinationip_ip_3 != ""):
            if len(destinationip_ip_3.split(".")) != 4:
                self.error_add_rule_3.setText("Không đúng định dạng IP đích")
                return
            else:
                for i in range(0,4):
                    if destinationip_ip_3.split(".")[i].isnumeric() is False:
                        self.error_add_rule_3.setText("Không đúng định dạng IP nguồn")
                        return
            cmd_dst_ip_3 = " --dst-ip "+destinationip_ip_3


        if(destinationip_port_3 != ""):
            if destinationip_port_3.isnumeric() is False:
                self.error_add_rule_3.setText("Không đúng định dạng cổng đích")
                return
            cmd_dst_port_3 = " --dst-port "+destinationip_port_3


        if (protocol_3 == "icmpv4") or (protocol_3 == "icmpv6") or (protocol_3 == "any"):
            cmd_src_port_3 = ""
            cmd_dst_port_3 = ""

        if self.status_3.isChecked():
            state_rule_3 = " --enable-rule"
        if self.action_3.isChecked():
            action_3 = " --rule-target allow"

        cmd = 'script\\firewall\\window_firewall.exe -A --protocol ' + protocol_3 + cmd_src_ip_3 + cmd_dst_ip_3 + cmd_src_port_3 + cmd_dst_port_3 + ' --program '+'"'+name_rule_3+'"' + state_rule_3 + action_3 + " --rule-name "+'"'+name_rule_3+'"'
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        mess = output.decode('ASCII')
        print(mess)
        if(mess.find(""""stdout": "b'Ok""") == -1):
            self.error_add_rule_3.setText("Thông tin không hợp lệ")
            return
        
        self.showProgramTraffic()
        self.main.setCurrentIndex(19)


    def dnsQueryList(self):
        data = [
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
            ["2423", "192.168.1.121", "google.com.vn", "15/02/2020", "14h:46 PM", "0.99977", "0.000223469"],
        ]

        self.dns_table.setColumnCount(7)
        self.dns_table.setRowCount(len(data))
        i = 0
        for data in data:
            for j in range(0,7):
                self.dns_table.setItem(i,j, QTableWidgetItem((data[j])))
            i=i+1


    def dgaLog(self):
        data = [
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
            ["2423", "twitter.com", "1.0", "0.0", "38", "11:05:18"],
        ]

        self.dga_log.setColumnCount(6)
        self.dga_log.setRowCount(len(data))
        i = 0
        for data in data:
            for j in range(0,6):
                self.dga_log.setItem(i,j, QTableWidgetItem((data[j])))
            i=i+1


    def showBlackList(self):
        cmd = 'py script/firewall/manual_input.py -L'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        dataStr = output.decode('ASCII')
        dataJson = json.loads(dataStr)
        ruleInput = dataJson["INPUT"]
        countItem = 0
        for data in ruleInput:
            if type(data["target"]) is dict:
                continue
            else:
                countItem = countItem + 1

        self.black_list.setColumnCount(7)
        self.black_list.setRowCount(countItem)
        # self.black_list.mouseReleaseEvent = self.removeInRule
        i = 0
        for data in ruleInput:
            if type(data["target"]) is dict:
                continue
            else:
                for key in data:
                    if key == "protocol":
                        self.black_list.setItem(i,0, QTableWidgetItem(data["protocol"]))
                    elif key == "iprange":
                        if("src-range" in data["iprange"]):
                            src_ip = data["iprange"]["src-range"].split("-")
                            if(len(src_ip) == 2 and src_ip[0] == src_ip[1]):
                                self.black_list.setItem(i,1, QTableWidgetItem(src_ip[0]))
                            else:
                                self.black_list.setItem(i,1, QTableWidgetItem(data["iprange"]["src-range"]))
                        if("dst-range" in data["iprange"]):
                            dst_ip = data["iprange"]["dst-range"].split("-")
                            if(len(dst_ip) == 2 and dst_ip[0] == dst_ip[1]):
                                self.black_list.setItem(i,2, QTableWidgetItem(dst_ip[0]))
                            else:
                                self.black_list.setItem(i,2, QTableWidgetItem(data["iprange"]["dst-range"]))

                    elif key == "target":
                        self.black_list.setItem(i,6, QTableWidgetItem(data["target"]))
                    else:
                        if(data[key]):
                            if("sport" in data[key]):
                                self.black_list.setItem(i,3, QTableWidgetItem(data[key]["sport"]))
                        if(data[key]):
                            if("dport" in data[key]):
                                self.black_list.setItem(i,4, QTableWidgetItem(data[key]["dport"]))
                i = i+1



    def showWhiteList(self):
        cmd = 'py script/firewall/manual_input.py -L'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        dataStr = output.decode('ASCII')
        dataJson = json.loads(dataStr)
        ruleInput = dataJson["OUTPUT"]

        countItem = 0
        for data in ruleInput:
            if type(data["target"]) is dict:
                continue
            else:
                countItem = countItem + 1

        self.white_list.setColumnCount(7)
        self.white_list.setRowCount(countItem)
        # self.white_list.mouseReleaseEvent = self.removeOutRule
        i = 0
        for data in ruleInput:
            if type(data["target"]) is dict:
                continue
            else:
                for key in data:
                    if key == "protocol":
                        self.white_list.setItem(i,0, QTableWidgetItem(data["protocol"]))
                    elif key == "iprange":
                        if("src-range" in data["iprange"]):
                            src_ip = data["iprange"]["src-range"].split("-")
                            if(len(src_ip) == 2 and src_ip[0] == src_ip[1]):
                                self.white_list.setItem(i,1, QTableWidgetItem(src_ip[0]))
                            else:
                                self.white_list.setItem(i,1, QTableWidgetItem(data["iprange"]["src-range"]))
                        if("dst-range" in data["iprange"]):
                            dst_ip = data["iprange"]["dst-range"].split("-")
                            if(len(dst_ip) == 2 and dst_ip[0] == dst_ip[1]):
                                self.white_list.setItem(i,2, QTableWidgetItem(dst_ip[0]))
                            else:
                                self.white_list.setItem(i,2, QTableWidgetItem(data["iprange"]["dst-range"]))

                    elif key == "target":
                        self.white_list.setItem(i,6, QTableWidgetItem(data["target"]))
                    else:
                        if(data[key]):
                            if("sport" in data[key]):
                                self.white_list.setItem(i,3, QTableWidgetItem(data[key]["sport"]))
                        if(data[key]):
                            if("dport" in data[key]):
                                self.white_list.setItem(i,4, QTableWidgetItem(data[key]["dport"]))
                i = i+1




    ################################################ end information ################################################

    ################################################# Applications ####################################################

    def getProcessApp(self):
        cmd = '.\powershell\process.ps1'
        p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        data = str(output).split("|||")
        del data[0]
        self.process_list_2.setColumnCount(5)
        self.process_list_2.setRowCount(len(data)-1)
        for i in range(0,len(data)-1):
            for j in range(0,5):
                if(j == 0):
                    button = QPushButton(self)
                    if (data[i].split('||')[j]).replace('\\n', '') == "chrome  ":
                        button.setIcon(QtGui.QIcon("icon/chrome.png"))
                    else:
                         button.setIcon(QtGui.QIcon("icon/unknow.png"))
                    button.setText(((data[i].split('||')[j]).replace('\\n', '')).replace("\\r",""))
                    button.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");
                    self.process_list_2.setCellWidget(i,0,button)
                    continue
                elif(j==3):
                    self.process_list_2.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '')))
                    continue
                elif(j==4):
                    self.process_list_2.setItem(i,j, QTableWidgetItem(((data[i].split('||')[j]).replace('\\n', '')).replace(" ","")))
                    continue
                else:
                    self.process_list_2.setItem(i,j, QTableWidgetItem((data[i].split('||')[j]).replace('\\n', '') + " %"))
                    continue



    def killProcessApp(self):
        indexes = self.process_list_2.selectionModel().selectedRows()
        for index in sorted(indexes):
            PID = self.process_list_2.item(index.row(), 4).text()
            cmd = "taskkill /PID "+PID+ " /F"
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                print(cmd)
                self.getProcessApp()
            except:
                print("access denied or process does not exist")
                self.getProcessApp()



    # def getDataApplications(self):
    #     layout = QGridLayout(self.list_application)
    #     layout.setVerticalSpacing(30)
    #     cmd = r'script/applications/window_app.exe'
    #     output = qx(cmd)
    #     dataStr = output.decode('utf8').replace("'", '"')
    #     jsonData = json.loads(dataStr)
    #     i = 0
    #     j = 0
    #     for data in jsonData:
    #         widget = QWidget()
    #         widget.setStyleSheet("QWidget {background: rgba(255,255,255,0.05); border-radius: 5px;} QLabel{background: transparent;} QWidget:hover {background: rgba(255,255,255,0.2);} QLabel:hover {background: transparent} QTextBrowser{background: transparent;} QTextBrowser:hover {background: transparent}")
    #         widget.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
    #         widget.setObjectName("application_number_"+str(i))
    #         widget.setFixedHeight(150)
    #         widget.setFixedWidth(150)
    #         icon = QLabel()
    #         if(data['icon'].find(".dll") != -1):
    #             try:
    #                 ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
    #                 ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
    #                 large, small = win32gui.ExtractIconEx(data['icon'].split(",")[0],0)
    #                 win32gui.DestroyIcon(large[0])
    #                 hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
    #                 hbmp = win32ui.CreateBitmap()
    #                 hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
    #                 hdc = hdc.CreateCompatibleDC()
    #                 hdc.SelectObject( hbmp )
    #                 hdc.DrawIcon( (0,0), small[0] )
    #                 hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+str(j)+".png" )
    #                 icon.setPixmap(QtGui.QPixmap("icon\\icon_app\\app"+str(i)+str(j)+".png"))
    #             except:
    #                 icon.setPixmap(QtGui.QPixmap("icon\\unknow.png"))
    #         elif(data['icon'].find(".exe,0") != -1):
    #             try:
    #                 ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
    #                 ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
    #                 large, small = win32gui.ExtractIconEx(data['icon'].split(",")[0],0)
    #                 win32gui.DestroyIcon(large[0])
    #                 hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
    #                 hbmp = win32ui.CreateBitmap()
    #                 hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
    #                 hdc = hdc.CreateCompatibleDC()
    #                 hdc.SelectObject( hbmp )
    #                 hdc.DrawIcon( (0,0), small[0] )
    #                 hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+str(j)+".png" )
    #                 icon.setPixmap(QtGui.QPixmap("icon\\icon_app\\app"+str(i)+str(j)+".png"))
    #             except:
    #                 icon.setPixmap(QtGui.QPixmap("icon\\unknow.png"))
    #         elif(data['icon'].find(".exe") != -1):
    #             try:
    #                 ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
    #                 ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
    #                 large, small = win32gui.ExtractIconEx(data['icon'],0)
    #                 win32gui.DestroyIcon(large[0])
    #                 hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
    #                 hbmp = win32ui.CreateBitmap()
    #                 hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
    #                 hdc = hdc.CreateCompatibleDC()
    #                 hdc.SelectObject( hbmp )
    #                 hdc.DrawIcon( (0,0), small[0] )
    #                 hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+str(j)+".png" )
    #                 icon.setPixmap(QtGui.QPixmap("icon\\icon_app\\app"+str(i)+str(j)+".png"))
    #             except:
    #                 icon.setPixmap(QtGui.QPixmap("icon\\unknow.png"))
    #         else:
    #             icon.setPixmap(QtGui.QPixmap("icon\\unknow.png"))
                
    #         icon.setFixedSize(65, 65)
    #         icon.setScaledContents(1)
    #         name = QTextBrowser()
    #         name.setText(data['application_name'])
    #         name.setAlignment(Qt.AlignCenter)
            
    #         layoutItem = QGridLayout(widget)
    #         layoutItem.addWidget(icon, 0, 0, alignment=QtCore.Qt.AlignCenter)
    #         layoutItem.addWidget(name, 1, 0, alignment=QtCore.Qt.AlignCenter)
    #         if(j == 4):
    #             i = i + 1
    #             j = 0
    #             layout.addWidget(widget, i, j)
    #             j = j + 1
    #         else:
    #             layout.addWidget(widget, i, j)
    #             j = j + 1


    def runApplication(self, instance):
        try:
            subprocess.call(self.path_app.text())
        except Exception as e:
            print(e)


    def removeApplication(self, instance):
        try:
            subprocess.call(self.uninstall_app.text())
        except Exception as e:
            print(e)


    def showListApplications(self):
        cmd = r'script/applications/window_app.exe'
        output = qx(cmd)
        dataStr = output.decode('utf8').replace("'", '"')
        jsonData = json.loads(dataStr)
        self.applications.setColumnCount(3)
        self.applications.setRowCount(len(jsonData))
        # self.applications.mouseReleaseEvent =lambda x : self.detailApplication(jsonData) 
        self.applications.doubleClicked.connect(lambda: self.detailApplication(jsonData))
        i = 0
        for data in jsonData:
            icon = QPushButton()
            icon.setIconSize(QtCore.QSize(22, 22))
            icon.setStyleSheet("QPushButton { background-color: transparent; text-align: left; padding-left: 7px;}");

            if(data['icon'].find(".dll") != -1):
                try:
                    ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
                    ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
                    large, small = win32gui.ExtractIconEx(data['icon'].split(",")[0],0)
                    win32gui.DestroyIcon(large[0])
                    hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
                    hbmp = win32ui.CreateBitmap()
                    hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
                    hdc = hdc.CreateCompatibleDC()
                    hdc.SelectObject( hbmp )
                    hdc.DrawIcon( (0,0), small[0] )
                    hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+".png" )
                    icon.setIcon(QtGui.QIcon("icon\\icon_app\\app"+str(i)+".png"))
                except:
                    icon.setIcon(QtGui.QIcon("icon\\unknow.png"))
            elif(data['icon'].find(".exe,0") != -1):
                try:
                    ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
                    ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
                    large, small = win32gui.ExtractIconEx(data['icon'].split(",")[0],0)
                    win32gui.DestroyIcon(large[0])
                    hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
                    hbmp = win32ui.CreateBitmap()
                    hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
                    hdc = hdc.CreateCompatibleDC()
                    hdc.SelectObject( hbmp )
                    hdc.DrawIcon( (0,0), small[0] )
                    hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+".png" )
                    icon.setIcon(QtGui.QIcon("icon\\icon_app\\app"+str(i)+".png"))
                except:
                    icon.setIcon(QtGui.QIcon("icon\\unknow.png"))
            elif(data['icon'].find(".exe") != -1):
                try:
                    ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
                    ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)
                    large, small = win32gui.ExtractIconEx(data['icon'],0)
                    win32gui.DestroyIcon(large[0])
                    hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
                    hbmp = win32ui.CreateBitmap()
                    hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
                    hdc = hdc.CreateCompatibleDC()
                    hdc.SelectObject( hbmp )
                    hdc.DrawIcon( (0,0), small[0] )
                    hbmp.SaveBitmapFile( hdc, "icon\\icon_app\\app"+str(i)+".png" )
                    icon.setIcon(QtGui.QIcon("icon\\icon_app\\app"+str(i)+".png"))
                except:
                    icon.setIcon(QtGui.QIcon("icon\\unknow.png"))
            else:
                icon.setIcon(QtGui.QIcon("icon\\unknow.png"))

            self.applications.setCellWidget(i,0,icon)
            self.applications.setItem(i,1, QTableWidgetItem(data['application_name']))
            self.applications.setItem(i,2, QTableWidgetItem(data['publisher']))
            i = i + 1


    def detailApplication(self,data):
        row = self.applications.selectionModel().currentIndex().row()
        column = self.applications.selectionModel().currentIndex().column()
        # try:
        #     self.icon_app.setPixmap(QtGui.QPixmap("icon\\icon_app\\app"+str(row)+".png"))
        # except:
        #     self.icon_app.setPixmap(QtGui.QPixmap("icon\\unknow.png"))

        try:
            f = open("icon\\icon_app\\app"+str(row)+".png")
            self.icon_app.setPixmap(QtGui.QPixmap("icon\\icon_app\\app"+str(row)+".png"))
        except:
            self.icon_app.setPixmap(QtGui.QPixmap("icon\\unknow.png"))

        self.name_application.setText(data[row]['application_name'])
        self.path_app.setText(data[row]['icon'].replace(",0",""))
        self.size_app.setText(str(data[row]['install_information']['size']))
        self.name_app.setText(data[row]['application_name'])
        try:
            self.version_app.setText(data[row]['current_version'])
        except:
            self.version_app.setText("")
        self.install_location.setText(data[row]['install_information']['install_location'])
        self.install_date.setText(data[row]['install_information']['install_date'])
        self.install_source.setText(data[row]['install_information']['install_source'])
        self.publisher_app.setText(data[row]['publisher'])
        self.uninstall_app.setText(data[row]['install_information']['uninstall_string'])
        self.main.setCurrentIndex(9)

        
    def showASecurityHole(self, instance):
        self.main.setCurrentIndex(22)
        with open('script/applications/security_hole.json') as outfile:
            data = json.load(outfile)
        self.table_security_hole.setColumnCount(2)
        self.table_security_hole.setRowCount(len(data)*13)
        for i in range(0, len(data)):
            self.table_security_hole.setItem(i*13, 0, QTableWidgetItem('index'))
            self.table_security_hole.setItem(i*13, 1, QTableWidgetItem(data[i]['index']))
            self.table_security_hole.setItem(i*13 + 1, 0, QTableWidgetItem('cve_id'))
            self.table_security_hole.setItem(i*13 + 1, 1, QTableWidgetItem(data[i]['cve_id']))
            self.table_security_hole.setItem(i*13 + 2, 0, QTableWidgetItem('cve_url'))
            self.table_security_hole.setItem(i*13 + 2, 1, QTableWidgetItem(data[i]['cve_url']))
            self.table_security_hole.setItem(i*13 + 3, 0, QTableWidgetItem('cwe_id'))
            self.table_security_hole.setItem(i*13 + 3, 1, QTableWidgetItem(data[i]['cwe_id']))
            self.table_security_hole.setItem(i*13 + 4, 0, QTableWidgetItem('cwe_url'))
            self.table_security_hole.setItem(i*13 + 4, 1, QTableWidgetItem(data[i]['cwe_url']))
            self.table_security_hole.setItem(i*13 + 5, 0, QTableWidgetItem('vulnerability_type'))
            self.table_security_hole.setItem(i*13 + 5, 1, QTableWidgetItem(data[i]['vulnerability_type']))
            self.table_security_hole.setItem(i*13 + 6, 0, QTableWidgetItem('publish_date'))
            self.table_security_hole.setItem(i*13 + 6, 1, QTableWidgetItem(data[i]['publish_date']))
            self.table_security_hole.setItem(i*13 + 7, 0, QTableWidgetItem('update_date'))
            self.table_security_hole.setItem(i*13 + 7, 1, QTableWidgetItem(data[i]['update_date']))
            self.table_security_hole.setItem(i*13 + 8, 0, QTableWidgetItem('cve_score'))
            self.table_security_hole.setItem(i*13 + 8, 1, QTableWidgetItem(data[i]['cve_score']))
            self.table_security_hole.setItem(i*13 + 9, 0, QTableWidgetItem('access'))
            self.table_security_hole.setItem(i*13 + 9, 1, QTableWidgetItem(data[i]['access']))
            self.table_security_hole.setItem(i*13 + 10, 0, QTableWidgetItem('complexcity'))
            self.table_security_hole.setItem(i*13 + 10, 1, QTableWidgetItem(data[i]['complexcity']))
            self.table_security_hole.setItem(i*13 + 11, 0, QTableWidgetItem('cve_summary'))
            self.table_security_hole.setItem(i*13 + 11, 1, QTableWidgetItem(data[i]['cve_summary']))
            self.table_security_hole.setItem(i*13 + 12, 0, QTableWidgetItem())


    

    #############################################ND Applications ####################################################################


    ################################################# REPORT  ###################################################################

    def show_report_list(self):
        layout = QGridLayout(self.report_list)
        data = [["Update of databases and application modules_0", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_1", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_2", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_3", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_4", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_5", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_6", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_7", "Completed", "Yesterday, 10:19 AM"],["Update of databases and application modules_8", "Completed", "Yesterday, 10:19 AM"], ["Update of databases and application modules_9", "Completed", "Yesterday, 10:19 AM"]]
        i = 0
        
        for data in data:
            widget = QWidget()
            widget.setStyleSheet("QWidget {background: rgba(255,255,255,0.1); border-radius: 5px;} QLabel{background: transparent;} QWidget:hover {background: rgba(255,255,255,0.2);} QLabel:hover {background: transparent}")
            widget.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            widget.setObjectName(str(i)+"||widget_report")
            widget.setFixedHeight(65)
            name = QLabel(data[0])
            name.setObjectName(str(i)+"||label_name_report")
            status = QLabel(data[1])
            status.setObjectName(str(i)+"||label_status_report")
            status.setStyleSheet("QLabel {color: #72ac57}")
            timeReport = QLabel(data[2])
            timeReport.setObjectName(str(i)+"||label_time_report")
            timeReport.setAlignment(Qt.AlignCenter | Qt.AlignRight);
            # widget.mouseReleaseEvent=lambda x: self.getInfoReport(name, widget)
            
            
            layoutItem = QGridLayout(widget)
            layoutItem.addWidget(name, 0, 0)
            layoutItem.addWidget(timeReport, 0, 1)
            layoutItem.addWidget(status, 1, 0)
            layout.addWidget(widget, i, 0)
            widget.mouseReleaseEvent=self.getInfoReport
            i=i+1



    def getInfoReport(self, event):
        hoveredWidget = QApplication.widgetAt(event.globalPos())
        numberReport = (hoveredWidget.objectName()).split("||")[0]
        print(self.report_list.findChild(QLabel,numberReport+"||label_name_report").text())


    def showTableReportMonitor(self, instance):
        self.main.setCurrentIndex(23)
        cmd = 'python script\\file_system\\demo_monitor.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_monitor.setColumnCount(5)
            self.table_report_monitor.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[5])
                self.table_report_monitor.setItem(i, 0, QTableWidgetItem(data[1]))
                self.table_report_monitor.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_monitor.setItem(i, 2, QTableWidgetItem(data[3]))
                self.table_report_monitor.setItem(i, 3, QTableWidgetItem(data[4]))
                self.table_report_monitor.setCellWidget(i,4,path)
                self.table_report_monitor.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                i = i + 1
        except Exception as e:
            print(e)



    def showTableReportIntegrity(self, instance):
        self.main.setCurrentIndex(24)
        cmd = 'python script\\file_system\\demo_integrity.py -a'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            data = json.loads(output.decode('ASCII'))['alert_list']
            self.table_report_integrity.setColumnCount(3)
            self.table_report_integrity.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/folder.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data[3])
                self.table_report_integrity.setCellWidget(i,0,path)
                self.table_report_integrity.setItem(i, 1, QTableWidgetItem(data[2]))
                self.table_report_integrity.item(i, 1).setForeground(QtGui.QColor(70, 178, 66))
                self.table_report_integrity.setItem(i, 2, QTableWidgetItem(data[1]))
                i = i + 1
        except Exception as e:
            print(e)



    def showTableReportVirus(self, instance):
        self.main.setCurrentIndex(25)
        with open('script/clamav_virus/log_virus.json') as outfile:
            data = json.load(outfile)
        try:
            self.table_report_virus.setColumnCount(2)
            self.table_report_virus.setRowCount(len(data))
            i = 0
            for data in data:
                path = QPushButton()
                path.setIcon(QtGui.QIcon("icon/bug.png"))
                path.setStyleSheet("QPushButton {text-align: left;}");
                path.setText(data["path"])
                self.table_report_virus.setCellWidget(i,0,path)
                self.table_report_virus.setItem(i, 1, QTableWidgetItem(data["time"]))
                i = i + 1
        except Exception as e:
            print(e)
        

    ############################################# end REPORT #######################################################



    def styleTable(self):
        # Hide left-header of table
        self.tableNetstat.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.tableNetstat.setSortingEnabled(True) 
        # Disable editing of cell
        self.tableNetstat.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.tableNetstat.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.tableNetstat.setShowGrid(False)
        self.tableNetstat.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set text-algin-left for header
        self.tableNetstat.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft) 

        # Hide left-header of table
        self.process_list.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.process_list.setSortingEnabled(True) 
        # Disable editing of cell
        self.process_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.process_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.process_list.setShowGrid(False)
        self.process_list.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents) 
        #set full width and height for table 
        self.process_list.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.process_list.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.process_list_2.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.process_list_2.setSortingEnabled(True) 
        # Disable editing of cell
        self.process_list_2.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.process_list_2.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.process_list_2.setShowGrid(False)
        self.process_list_2.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents) 
        #set full width and height for table 
        self.process_list_2.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.process_list_2.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.incoming_traffic.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.incoming_traffic.setSortingEnabled(True) 
        # Disable editing of cell
        self.incoming_traffic.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.incoming_traffic.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.incoming_traffic.setShowGrid(False)
        # self.incoming_traffic.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set text-algin-left for header
        self.incoming_traffic.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.out_traffic.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.out_traffic.setSortingEnabled(True) 
        # Disable editing of cell
        self.out_traffic.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.out_traffic.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.out_traffic.setShowGrid(False)
        # self.out_traffic.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set text-algin-left for header
        self.out_traffic.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.program_traffic.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.program_traffic.setSortingEnabled(True) 
        # Disable editing of cell
        self.program_traffic.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.program_traffic.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.program_traffic.setShowGrid(False)
        # self.out_traffic.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set text-algin-left for header
        self.program_traffic.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.config_hardware.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.config_hardware.setSortingEnabled(True) 
        # Disable editing of cell
        self.config_hardware.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.config_hardware.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.config_hardware.setShowGrid(False)
        self.config_hardware.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.config_hardware.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.config_hardware.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.table_disk.verticalHeader().setVisible(False)
        # Hide top-header of table
        # self.table_disk.horizontalHeader().setVisible(False)
        # Sort by row when click header
        self.table_disk.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_disk.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_disk.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_disk.setShowGrid(False)
        self.table_disk.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.table_disk.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_disk.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)
        self.table_disk.resizeColumnToContents(0)

        # Hide left-header of table
        self.dns_table.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.dns_table.setSortingEnabled(True) 
        # Disable editing of cell
        self.dns_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.dns_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.dns_table.setShowGrid(False)
        self.dns_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.dns_table.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.dns_table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.dga_log.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.dga_log.setSortingEnabled(True) 
        # Disable editing of cell
        self.dga_log.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.dga_log.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.dga_log.setShowGrid(False)
        self.dga_log.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.dga_log.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.dga_log.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.black_list.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.black_list.setSortingEnabled(True) 
        # Disable editing of cell
        self.black_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.black_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.black_list.setShowGrid(False)
        self.black_list.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.black_list.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.black_list.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.white_list.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.white_list.setSortingEnabled(True) 
        # Disable editing of cell
        self.white_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.white_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.white_list.setShowGrid(False)
        self.white_list.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.white_list.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.white_list.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.report_table.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.report_table.setSortingEnabled(True) 
        # Disable editing of cell
        self.report_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.report_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.report_table.setShowGrid(False)
        self.report_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.report_table.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.report_table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.applications.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.applications.setSortingEnabled(True) 
        # Disable editing of cell
        self.applications.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.applications.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.applications.setShowGrid(False)
        self.applications.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.applications.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.applications.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.path_list.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.path_list.setSortingEnabled(True) 
        # Disable editing of cell
        self.path_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.path_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.path_list.setShowGrid(False)
        self.path_list.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.path_list.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.path_list.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.path_list_monitor.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.path_list_monitor.setSortingEnabled(True) 
        # Disable editing of cell
        self.path_list_monitor.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.path_list_monitor.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.path_list_monitor.setShowGrid(False)
        self.path_list_monitor.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.path_list_monitor.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.path_list_monitor.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.list_file_scan.verticalHeader().setVisible(False)
        # Hide top-header of table
        self.list_file_scan.horizontalHeader().setVisible(False)
        # Sort by row when click header
        self.list_file_scan.setSortingEnabled(True) 
        # Disable editing of cell
        self.list_file_scan.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.list_file_scan.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.list_file_scan.setShowGrid(False)
        self.list_file_scan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.list_file_scan.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.list_file_scan.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        # Hide left-header of table
        self.table_virus.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_virus.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_virus.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_virus.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_virus.setShowGrid(False)
        self.table_virus.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.table_virus.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_virus.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)

        
        # Hide left-header of table
        self.table_security_hole.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_security_hole.setSortingEnabled(True) 
        # Hide top-header of table
        self.table_security_hole.horizontalHeader().setVisible(False)
        # Disable editing of cell
        self.table_security_hole.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_security_hole.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_security_hole.setShowGrid(False)
        # self.table_security_hole.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.table_security_hole.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_security_hole.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)
        

        # Hide left-header of table
        self.table_report_monitor.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_report_monitor.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_report_monitor.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_report_monitor.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_report_monitor.setShowGrid(False)
        self.table_report_monitor.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.table_report_monitor.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_report_monitor.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)


        # Hide left-header of table
        self.table_report_integrity.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_report_integrity.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_report_integrity.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_report_integrity.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_report_integrity.setShowGrid(False)
        self.table_report_integrity.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        #set full width and height for table 
        self.table_report_integrity.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_report_integrity.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)


        
        # Hide left-header of table
        self.table_report_virus.verticalHeader().setVisible(False)
        # Sort by row when click header
        self.table_report_virus.setSortingEnabled(True) 
        # Disable editing of cell
        self.table_report_virus.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # set Highlight of row when click
        self.table_report_virus.setSelectionBehavior(QAbstractItemView.SelectRows)
        # remove space between columns and row 
        self.table_report_virus.setShowGrid(False)
        #set full width and height for table 
        self.table_report_virus.horizontalHeader().setStretchLastSection(True)
        #set text-algin-left for header
        self.table_report_virus.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)
        #set width for column
        self.table_report_virus.setColumnWidth(0, 350)


        
        #resize to contents for header 
        self.network.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        #set tab bar of QTabWidget is full gird
        # self.information_management.tabBar().setExpanding (True)


#==============================trantison animate -\================================#


# class ThreadClamav (QThread):
#     def __init__(self, parent=None):
#         QThread.__init__(self, parent=parent)

#     def run(self):
#         try:
#             subprocess.Popen('script\\clamav-0.101.0-win-x64-portable\\clamd.exe')
#         except Exception as e:
#             print(e)


class FaderWidget(QWidget):

    def __init__(self, old_widget, new_widget):
    
        QWidget.__init__(self, new_widget)
        
        self.old_pixmap = QPixmap(new_widget.size())
        old_widget.render(self.old_pixmap)
        self.pixmap_opacity = 1
        
        self.timeline = QTimeLine()
        self.timeline.valueChanged.connect(self.animate)
        self.timeline.finished.connect(self.close)
        self.timeline.setDuration(300)
        self.timeline.start()
        
        self.resize(new_widget.size())
        self.show()
    
    def paintEvent(self, event):
    
        painter = QPainter()
        painter.begin(self)
        painter.setOpacity(self.pixmap_opacity)
        painter.drawPixmap(0, 0, self.old_pixmap)
        painter.end()
    
    def animate(self, value):
    
        self.pixmap_opacity = 1.0 - value
        self.repaint()


#============================== end trantison animate -\================================#


class ThreadChartNetWork (threading.Thread):
    def __init__(self, window, card):
        threading.Thread.__init__(self)
        self.window=window
        self.card = card
        self.counter = 0

        self.X = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,37,39,40]
        self.Y = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        self.Y1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    def getData(self):
        return self.X, self.Y, self.Y1

    def getCard(self):
        return self.card

    def run(self):
        byte = psutil.net_io_counters(pernic=True)
        
        in_byte = byte[self.card][0]
        out_byte = byte[self.card][1]
        
        self.name = "threadChart"
        # print ("Starting " + self.name)

        global gcard
        global check_thread_chart_network
        check_thread_chart_network = 1
        while check_thread_chart_network == 1:
            
            tx = round((in_byte/1024)/1024,2)

            if self.card == gcard:
                self.window.card_name.setText(self.card)
                self.window.tx.setText(" " + str(tx) + " Mbps") 
            
            rx = round((out_byte/1024)/1024,2)

            if self.card == gcard:
                self.window.card_name.setText(self.card)
                self.window.rx.setText(" " + str(rx) + " Mbps")

            self.Y.append(tx)
            self.Y.pop(0)

            self.Y1.append(rx)
            self.Y1.pop(0)

            if self.card == gcard:
                self.window.chart_network.canvas.axes.clear()
                self.window.chart_network.canvas.figure.set_facecolor("#121416")
                self.window.chart_network.canvas.axes.patch.set_alpha(0.0)
                self.window.chart_network.canvas.axes.figure.set_facecolor('None')
                self.window.chart_network.canvas.axes.tick_params(labelcolor='#c7c7c9')
                self.window.chart_network.canvas.axes.set_xticklabels([])
                self.window.chart_network.canvas.axes.plot(self.X, self.Y, color='#f07d47')
                self.window.chart_network.canvas.axes.plot(self.X, self.Y1, color='#87ceeb')
                self.window.chart_network.canvas.axes.fill_between(self.X, 0, self.Y, color='#ff9292', alpha=0.2)
                self.window.chart_network.canvas.axes.fill_between(self.X, 0, self.Y1, color='white', alpha=0.1)
                self.window.chart_network.canvas.draw()
            time.sleep(1.5)
        sys.exit()

class ThreadChartCPU (threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window=window
    def run(self):
        self.name = "threadChartCPU"
        # print ("Starting " + self.name)
        X = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,37,39,40]
        Y = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

        global check_thread_chart_cpu
        check_thread_chart_cpu = 1
        while check_thread_chart_cpu == 1:

            cmd = '.\powershell\status.ps1'
            p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("|||")       
            cpu = float(((data[1].split(":")[1]).split("%")[0]).replace(" ",""))
            self.window.cpu_value.setText(str(cpu) + " %")
            Y.append(cpu)
            Y.pop(0)

            self.window.chart_cpu.canvas.axes.clear()
            self.window.chart_cpu.canvas.figure.set_facecolor("#121416")
            self.window.chart_cpu.canvas.axes.patch.set_alpha(0.0)
            self.window.chart_cpu.canvas.axes.figure.set_facecolor('None')
            self.window.chart_cpu.canvas.axes.tick_params(labelcolor='#c7c7c9')
            self.window.chart_cpu.canvas.axes.set_xticklabels([])
            self.window.chart_cpu.canvas.axes.set_yticklabels([])
            self.window.chart_cpu.canvas.axes.set_ylim(0, 100)
            self.window.chart_cpu.canvas.axes.plot(X, Y, color='#f07d47')
            self.window.chart_cpu.canvas.axes.fill_between(X, 0, Y, color='#f07d47', alpha=0.2)
            self.window.chart_cpu.canvas.draw()
            time.sleep(1.5)
        sys.exit()

class ThreadChartRAM (threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window=window
    def run(self):
        self.name = "threadChartRAM"
        # print ("Starting " + self.name)
        X = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,37,39,40]
        Y = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

        global check_thread_chart_ram
        check_thread_chart_ram = 1
        while check_thread_chart_ram == 1:
            cmd ='.\powershell\status.ps1'
            p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("|||")      
            ramUsed = float((data[2].split("||")[0]).split("RAM Usage :")[1])
            ramTotal = float(data[2].split("||")[1])
            self.window.ram_value.setText(str(ramUsed) + " Mb")
            self.window.ram_total.setText(str(ramTotal) + " Mb")
            Y.append(ramUsed)
            Y.pop(0)

            self.window.chart_ram.canvas.axes.clear()
            self.window.chart_ram.canvas.figure.set_facecolor("#121416")
            self.window.chart_ram.canvas.axes.patch.set_alpha(0.0)
            self.window.chart_ram.canvas.axes.figure.set_facecolor('None')
            self.window.chart_ram.canvas.axes.tick_params(labelcolor='#c7c7c9')
            self.window.chart_ram.canvas.axes.set_xticklabels([])
            self.window.chart_ram.canvas.axes.set_yticklabels([])
            self.window.chart_ram.canvas.axes.set_ylim(0, ramTotal)
            self.window.chart_ram.canvas.axes.plot(X, Y, color='#A9D0F5')
            self.window.chart_ram.canvas.axes.fill_between(X, 0, Y, color='white', alpha=0.2)
            self.window.chart_ram.canvas.draw()
            sleep(1.5)
        sys.exit()


class ThreadTableProcess (QThread):
    updateProcess = pyqtSignal(list)
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        while True: 
            cmd = '.\powershell\process.ps1'
            p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("|||")
            del data[0]
            self.updateProcess.emit(data)
            time.sleep(8)
        sys.exit()


class ThreadUpdateInfo (QThread):
    updateInfo = pyqtSignal(str,str,str,str)
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        while True: 
            cmd = '.\powershell\status.ps1'
            p = subprocess.Popen(["powershell.exe" ,cmd], stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("|||")
            
            time_info = strftime("%b %d %Y %H:%M:%S")
            up_time = data[0].split(":")[1]
            swap = data[3].split("||")[2]
            process = data[4].replace('\\n', '').replace('\\r', '').lstrip("\'")
            self.updateInfo.emit(time_info, up_time, process, swap)
            time.sleep(10)
        sys.exit()


class ThreadClamdStart(QThread):
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        
    def run(self):
        cmd = "script\\clamav-0.101.0-win-x64-portable\\clamd.exe"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        sys.exit()



class infoNetwork (threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window=window
    def run(self):
        window.update_info_network.click()
        sys.exit()


# class getListPathFullScan (threading.Thread):
#     def __init__(self, window):
#         threading.Thread.__init__(self)
#         self.window=window
#     def run(self):
#         self.name = "getListPathFullScan"
#         global listPathFullScan
#         cmd = "wmic logicaldisk get size,freespace,caption"
#         p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
#         (output, err) = p.communicate()
#         p_status = p.wait()
#         data = str(output).split("\\n")
#         data.pop(0)
#         del data[-1]
#         del data[-1]
#         files = []
#         for i in range(0,len(data)):
#             pathDisk = (data[i].split())[0].replace(":",":\\")
#             for r, d, f in os.walk(pathDisk):
#                 for file in f:
#                     print(file)
#                     listPathFullScan.append(os.path.join(r, file))
#             print(pathDisk)
#             i=i+1 
#         global doneGetPath
#         doneGetPath = 1

class processBarQuickScan (QThread):
    updateVirus = pyqtSignal(str)
    updateIndex = pyqtSignal(str)
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    completeScan = pyqtSignal()
    endQuickScanVisible = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        self.name = "thread_processBarQuickScan"
        try:
            virus = 0
            i = 0

            cmd = "wmic logicaldisk get size,freespace,caption"
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("\\n")
            data.pop(0)
            totalDisk = len(data)
            del data[-1]
            del data[-1]
            files = []
            index = 0
            count = 0

            #get count files on window
            for i in range(0,totalDisk-2):
                pathDisk = (data[i].split())[0].replace(":",":\\")
                for r, d, f in os.walk(pathDisk):
                    if(r.find("$RECYCLE.BIN") != -1):
                        continue
                    for file in f:
                        count = count + 1

            print(count)
            self.endQuickScanVisible.emit()
            global listVirusQuickScan
            for i in range(0,totalDisk):
                pathDisk = (data[i].split())[0].replace(":",":\\")
                for r, d, f in os.walk(pathDisk):
                    if(r.find("$RECYCLE.BIN") != -1):
                        continue
                    for file in f:
                        while(isStopQuickScan == 1):
                            time.sleep(0.5)
                            continue
                        if(isStopQuickScan == 2):
                            self.completeScan.emit()
                            return
                        path = os.path.join(r, file)
                        pathFile = path.replace("/","\\")
                        cmd = "script\\clamav-0.101.0-win-x64-portable\\clamdscan.exe "+'"'+pathFile+'"'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        # print(output)
                        state = str(output).find("Infected files: 1")
                        stateOk = str(output).find(": OK")
                        if(state != -1):
                            virus = virus + 1
                            try:
                                self.updateVirus.emit(str(virus))
                                self.addVirusToLog(pathFile, str(datetime.datetime.now()))
                                listVirusQuickScan.append({"path": pathFile, "time": str(datetime.datetime.now())})
                            except Exception as e:
                                print(e)
                        try:
                            self.updatePath.emit(path)
                            if(stateOk != -1):
                                index = index + 1 
                                self.updateIndex.emit(str(index))   
                        except Exception as e:
                            print(e)
                        i = i + 1
                        self.updateProcessBar.emit(int((i/count)*100))

            if(len(listVirusQuickScan) > 0):
                ThreadsendReportToServer = sendReportToServer(listVirusQuickScan)
                ThreadsendReportToServer.start()
            self.completeScan.emit()
        except Exception as e:
            print(e)


    def addVirusToLog(self, virus, time):
        a_dict = {"path": virus, "time": time}

        with open('script/clamav_virus/log_virus.json') as f:
            data = json.load(f)

        data.append(a_dict)

        with open('script/clamav_virus/log_virus.json', 'w') as f:
            json.dump(data, f)

class processBarFullScan (QThread):
    updateVirus = pyqtSignal(str)
    updateIndex = pyqtSignal(str)
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    completeScan = pyqtSignal()
    endFullScanVisible = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        self.name = "thread_processBarFullScan"
        try:
            virus = 0
            i = 0

            cmd = "wmic logicaldisk get size,freespace,caption"
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()
            data = str(output).split("\\n")
            data.pop(0)
            totalDisk = len(data)
            del data[-1]
            del data[-1]
            files = []
            index = 0
            count = 0
            global listVirusFullScan

            #get count files on window
            for i in range(0,totalDisk-2):
                pathDisk = (data[i].split())[0].replace(":",":\\")
                for r, d, f in os.walk(pathDisk):
                    if(r.find("$RECYCLE.BIN") != -1):
                        continue
                    for file in f:
                        count = count + 1

            print(count)
            self.endFullScanVisible.emit()
            for i in range(0,totalDisk-2):
                pathDisk = (data[i].split())[0].replace(":",":\\")
                for r, d, f in os.walk(pathDisk):
                    if(r.find("$RECYCLE.BIN") != -1):
                        continue
                    for file in f:
                        while(isStopFullScan == 1):
                            time.sleep(0.5)
                            continue
                        if(isStopFullScan == 2):
                            self.completeScan.emit()
                            return
                        path = os.path.join(r, file)
                        pathFile = path.replace("/","\\")
                        cmd = "script\\clamav-0.101.0-win-x64-portable\\clamdscan.exe "+'"'+pathFile+'"'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        # print(output)
                        state = str(output).find("Infected files: 1")
                        stateOk = str(output).find(": OK")
                        if(state != -1):
                            virus = virus + 1
                            try:
                                self.updateVirus.emit(str(virus))
                                self.addVirusToLog(pathFile, str(datetime.datetime.now()))
                                listVirusFullScan.append({"path": pathFile, "time": str(datetime.datetime.now())})
                            except Exception as e:
                                print(e)
                            virus = virus + 1
                        try:
                            self.updatePath.emit(path)
                            if(stateOk != -1):
                                index = index + 1 
                                self.updateIndex.emit(str(index))  
                        except Exception as e:
                            print(e)
                        self.updateProcessBar.emit(int((i/count)*100))

            if(len(listVirusFullScan) > 0):
                ThreadsendReportToServer = sendReportToServer(listVirusFullScan)
                ThreadsendReportToServer.start()
            self.completeScan.emit()
        except Exception as e:
            print(e)


    def addVirusToLog(self, virus, time):
        a_dict = {"path": virus, "time": time}

        with open('script/clamav_virus/log_virus.json') as f:
            data = json.load(f)

        data.append(a_dict)

        with open('script/clamav_virus/log_virus.json', 'w') as f:
            json.dump(data, f)


class ThreadSelectiveScan (QThread):
    updateVirus = pyqtSignal(str)
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    completeScan = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)

    def run(self):
        try:
            self.name = "thread_selectiveScan"
            global listVirusSelectiveScan
            global listScan
            virus = 0
            i = 0
            index = 0
            count = 0

            #get count files selected
            for data in listScan:
                if(data[1] == 0):   
                    count = count + 1
                else:
                    for r, d, f in os.walk(data[0]):
                        if(r.find("$RECYCLE.BIN") != -1):
                            continue
                        for file in f:
                            count = count + 1

            print(count)

            for data in listScan:
                if(data[1] == 0):
                    self.updatePath.emit(data[0])
                    file = data[0].replace("/","\\")
                    cmd = "script\\clamav-0.101.0-win-x64-portable\\clamdscan.exe "+'"'+file+'"'
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()
                    index = index + 1
                    self.updateProcessBar.emit(int((index/count)*100))
                    state = str(output).find("Infected files: 1")
                    if(state != -1):
                        listVirusSelectiveScan.append({"path": pathFile, "time": str(datetime.datetime.now())})
                        try:
                            self.updateVirus.emit("Tìm thấy "+str(virus+1)+" tệp độc hại")
                            self.addVirusToLog(pathFile, str(datetime.datetime.now()))
                        except Exception as e:
                            print(e)
                        virus = virus + 1
                else:
                    for r, d, f in os.walk(data[0]):
                        if(r.find("$RECYCLE.BIN") != -1):
                            continue
                        for file in f:
                            path = os.path.join(r, file)
                            pathFile = path.replace("/","\\")
                            self.updatePath.emit(path)
                            cmd = "script\\clamav-0.101.0-win-x64-portable\\clamdscan.exe "+'"'+pathFile+'"'
                            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                            (output, err) = p.communicate()
                            p_status = p.wait()
                            # print(output)
                            index = index+1
                            self.updateProcessBar.emit(int((index/count)*100))
                            state = str(output).find("Infected files: 1")
                            if(state != -1):
                                listVirusSelectiveScan.append({"path": pathFile, "time": str(datetime.datetime.now())})
                                self.addVirusToLog(pathFile, str(datetime.datetime.now()))
                                try:
                                    self.updateVirus.emit("Tìm thấy "+str(virus+1)+" tệp độc hại")
                                except Exception as e:
                                    print(e)
                                virus = virus + 1

            if(len(listVirusSelectiveScan) > 0):
                ThreadsendReportToServer = sendReportToServer(listVirusSelectiveScan)
                ThreadsendReportToServer.start()
            self.completeScan.emit()
        except Exception as e:
            print(e)

    def addVirusToLog(self, virus, time):
        a_dict = {"path": virus, "time": time}

        with open('script/clamav_virus/log_virus.json') as f:
            data = json.load(f)

        data.append(a_dict)

        with open('script/clamav_virus/log_virus.json', 'w') as f:
            json.dump(data, f)



class sendReportToServer (threading.Thread):
    def __init__(self, listVirus):
        threading.Thread.__init__(self)
        self.listVirus=listVirus
    def run(self):
        try:
            # defining the api-endpoint  
            API_ENDPOINT = "http://dascam.com.vn:8000/virus-scan"
            # data to be sent to api 
            data = self.listVirus
              
            # sending post request and saving response as response object 
            r = requests.post(url = API_ENDPOINT, data = data) 
              
            # extracting response text  
            pastebin_url = r.text 
            print("The pastebin URL is:%s"%pastebin_url) 
        except Exception as e:
            print(e)


class ThreadEncryptFolder (QThread):
    updatePath = pyqtSignal(str)
    updateProcessBar = pyqtSignal(int)
    updateIndex = pyqtSignal(str)
    completeCrypt = pyqtSignal()

    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        global eventCrypt
        global passwordCrpyt
        global pathCrypt
        self.path=pathCrypt
        self.password=passwordCrpyt
        self.event=eventCrypt


    def run(self):
        self.name = "thread_Encrypt_folder"

        count = 0
        for r, d, f in os.walk(self.path):
            for file in f:
                count=count+1

        totalFile = count
        i = 0
        succ = 0

        if(self.event == "encode"):
            for r, d, f in os.walk(self.path):
                for file in f:
                    filePath = os.path.join(r, file)
                    self.updatePath.emit("Tệp tin: "+filePath)
                    try:
                        cmd = 'python script\\file_system\\crypto.py -e -f ' '"'+filePath+'"' + ' "'+self.password+'"'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        state = str(output).find("Done encrypt file")
                        if state != -1:
                            self.updateProcessBar.emit(int(i*(100/totalFile))) 
                            succ=succ+1
                            self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                        else:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))
                            self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                            print(f+" file encryption failed")

                    except Exception as e:
                        self.updateProcessBar.emit(int(i*(100/totalFile)))
                        self.updateIndex.emit("Mã hóa thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                        print(e)
                        i = i + 1
            self.completeCrypt.emit()
        else:
            for r, d, f in os.walk(self.path):
                for file in f:
                    filePath = os.path.join(r, file)
                    self.updatePath.emit("Tệp tin: "+filePath)
                    try:
                        cmd = 'python script\\file_system\\crypto.py -d -f ' '"'+filePath+'"' + ' "'+self.password+'"'+' 2'
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()
                        state = str(output).find("Done decrypt file")
                        if state != -1:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))  
                            succ=succ+1
                            self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                        else:
                            self.updateProcessBar.emit(int(i*(100/totalFile)))
                            self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                            i = i + 1
                            print(f+" file decryption failed")

                    except Exception as e:
                        self.updateProcessBar.emit(int(i*(100/totalFile)))
                        self.updateIndex.emit("Giải mã thành công "+str(succ)+" tệp của "+str(totalFile)+" tệp.")
                        print(e)
                        i = i + 1
            self.completeCrypt.emit()



class ThreadscanIntegrity (QThread):
    updateReportScan = pyqtSignal()
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
    def run(self):
        while(True):
            # lay danh sach tep tin/thu muc kiem tra tinh toan ven
            cmd = 'python script\\file_system\\demo_integrity.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if(p_status == 0):
                data = json.loads(output.decode('ASCII'))['check_list']
                for d in data:
                    cmd = 'python script\\file_system\\demo_integrity.py -s ' + '"'+d[2]+'"'+" "+str(d[1])
                    print(cmd)
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()
                    print(output)
            self.updateReportScan.emit()
            time.sleep(60)


# class sendReportIntegrityToServer (threading.Thread):
#     def __init__(self, alert):
#         threading.Thread.__init__(self)
#         self.alert=alert
#     def run(self):
#         try:
#             print(self.alert)
#             # defining the api-endpoint  
#             API_ENDPOINT = "http://dascam.com.vn:8000/integrity-update"
#             # data to be sent to api 
#             data = self.alert
              
#             # sending post request and saving response as response object 
#             r = requests.post(url = API_ENDPOINT, json = data) 
              
#             # extracting response text  
#             pastebin_url = r.text 
#             print("The pastebin URL is:%s"%pastebin_url) 
#         except Exception as e:
#             print(e)




class ThreadscanMonitor (threading.Thread):
    def __init__(self, window):
        threading.Thread.__init__(self)
        self.window=window
    def run(self):
        while(True):
            # Tim id bao cao moi nhat
            cmdGetId = 'python script\\file_system\\demo_monitor.py -e'
            pID = subprocess.Popen(cmdGetId, stdout=subprocess.PIPE, shell=True)
            (outputId, err) = pID.communicate()
            pID_status = pID.wait()
            ID = json.loads(outputId.decode('ASCII'))['last_alert_id']

            # lay danh sach tep tin/thu muc theo doi
            cmd = 'python script\\file_system\\demo_monitor.py -l'
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            # Vong lap quet tung tep tin/ thu muc
            if(p_status == 0):
                data = json.loads(output.decode('ASCII'))['moniter_list']
                for d in data:
                    cmd = 'python script\\file_system\\demo_monitor.py -s ' + '"'+d[2]+'"'+" "+str(d[1])
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                    (output, err) = p.communicate()
                    p_status = p.wait()

            # lay danh sach bao cao phat hien thay doi vua quet
            # cmd = 'python script\\file_system\\demo_monitor.py -a '+str(ID)
            # p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            # (output, err) = p.communicate()
            # p_status = p.wait()
            # alert = json.loads(output.decode('ASCII'))['alert_list']
            # if(len(alert)>0):
            #     alertSend = json.loads(output.decode('ASCII'))
            #     ThreadsendReportMonitorToServer = sendReportMonitorToServer(alertSend)
            #     ThreadsendReportMonitorToServer.start()

            time.sleep(3600)


# class sendReportMonitorToServer (threading.Thread):
#     def __init__(self, alert):
#         threading.Thread.__init__(self)
#         self.alert=alert
#     def run(self):
#         try:
#             print(self.alert)
#             # defining the api-endpoint  
#             API_ENDPOINT = "http://dascam.com.vn:8000/moniter-update"
#             # data to be sent to api 
#             data = self.alert
              
#             # sending post request and saving response as response object 
#             r = requests.post(url = API_ENDPOINT, json = data) 
              
#             # extracting response text  
#             pastebin_url = r.text 
#             print("The pastebin URL is:%s"%pastebin_url) 
#         except Exception as e:
#             print(e)

                


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # fontWindow = QFont("Courier", 8, QFont.Bold, True);
    # app.setFont(fontWindow)
    font = QFont()
    font.setPixelSize(13);
    font.setFamily(font.defaultFamily())
    app.setFont(font)
    window = LoadingApp()
    window.show()

    sys.exit(app.exec_())

