import os
import re
import json
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone as dt_timezone
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from core.base_module import BaseOSINTModule

# ============================================================
# DATABASE GRANULAR OFFLINE HLR & CARRIER TELEKOMUNIKASI INDONESIA
# (Mencakup Prefiks 4, 5, dan 6 Digit dengan Pemetaan Regional Presisi)
# ============================================================
INDONESIA_HLR_GRANULAR_DB = {
    # ============================================================
    # 1. TELKOMSEL (MCC: 510, MNC: 10)
    # ============================================================
    # --- Kartu Halo (Postpaid / Corporate) ---
    "0811": {"carrier": "Telkomsel", "brand": "Kartu Halo (Postpaid / Corporate)", "mcc": "510", "mnc": "10", "region": "Nasional / Korporat", "network": "GSM / 4G / 5G"},

    # --- simPATI / Halo (0812) ---
    "08121": {"carrier": "Telkomsel", "brand": "simPATI / Halo", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten (Jakarta, Tangerang, Serang)", "network": "GSM / 4G / 5G"},
    "08122": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Bandung, Cirebon, Tasikmalaya)", "network": "GSM / 4G / 5G"},
    "08123": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa Timur & Madura (Surabaya, Malang, Jember)", "network": "GSM / 4G / 5G"},
    "08124": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sulawesi, Maluku & Papua (Makassar, Manado, Jayapura)", "network": "GSM / 4G / 5G"},
    "08125": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Kalimantan (Balikpapan, Banjarmasin, Pontianak)", "network": "GSM / 4G / 5G"},
    "08126": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Utara (Medan, Banda Aceh, Pematangsiantar)", "network": "GSM / 4G / 5G"},
    "08127": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Selatan & Tengah (Palembang, Lampung, Pekanbaru)", "network": "GSM / 4G / 5G"},
    "08128": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jabodetabek (Jakarta, Depok, Bekasi)", "network": "GSM / 4G / 5G"},
    "08129": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten (Bogor, Tangerang, Lebak)", "network": "GSM / 4G / 5G"},
    "0812": {"carrier": "Telkomsel", "brand": "simPATI / Halo", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Jawa", "network": "GSM / 4G / 5G"},

    # --- simPATI (0813) ---
    "08131": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten", "network": "GSM / 4G / 5G"},
    "08132": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa Barat & Jawa Tengah (Bandung, Semarang, Solo)", "network": "GSM / 4G / 5G"},
    "08133": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa Timur, Bali & Nusa Tenggara (Surabaya, Denpasar)", "network": "GSM / 4G / 5G"},
    "08134": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sulawesi & Kalimantan", "network": "GSM / 4G / 5G"},
    "08135": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Kalimantan & Indonesia Timur", "network": "GSM / 4G / 5G"},
    "08136": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Utara & Riau (Medan, Batam, Pekanbaru)", "network": "GSM / 4G / 5G"},
    "08137": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Selatan & Barat (Padang, Palembang, Jambi)", "network": "GSM / 4G / 5G"},
    "08138": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jabodetabek (Jakarta, Bekasi, Depok)", "network": "GSM / 4G / 5G"},
    "08139": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa Tengah & DI Yogyakarta (Semarang, Solo, Jogja)", "network": "GSM / 4G / 5G"},
    "0813": {"carrier": "Telkomsel", "brand": "simPATI", "mcc": "510", "mnc": "10", "region": "Jawa & Sumatera", "network": "GSM / 4G / 5G"},

    # --- simPATI Nusantara (0821) ---
    "08211": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten (Jakarta, Tangerang)", "network": "GSM / 4G / 5G"},
    "08212": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Bandung, Bekasi, Karawang)", "network": "GSM / 4G / 5G"},
    "08213": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jawa Tengah & DI Yogyakarta (Semarang, Jogja)", "network": "GSM / 4G / 5G"},
    "08214": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jawa Timur, Bali & NTB (Surabaya, Malang, Mataram)", "network": "GSM / 4G / 5G"},
    "08215": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Kalimantan (Samarinda, Balikpapan, Pontianak)", "network": "GSM / 4G / 5G"},
    "08216": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Utara (Medan, Aceh, Sibolga)", "network": "GSM / 4G / 5G"},
    "08217": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Tengah & Selatan (Pekanbaru, Padang, Palembang)", "network": "GSM / 4G / 5G"},
    "08218": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Sulawesi (Makassar, Manado, Palu)", "network": "GSM / 4G / 5G"},
    "08219": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Sulawesi Selatan, Tenggara & Maluku", "network": "GSM / 4G / 5G"},
    "0821": {"carrier": "Telkomsel", "brand": "simPATI Nusantara", "mcc": "510", "mnc": "10", "region": "Jabodetabek / Jawa Barat / Banten", "network": "GSM / 4G / 5G"},

    # --- simPATI / Loop (0822) ---
    "082260": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Jawa Barat (Bogor, Sukabumi, Depok)", "network": "GSM / 4G / 5G"},
    "082261": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Bandung, Cimahi, Garut)", "network": "GSM / 4G / 5G"},
    "082262": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Tasikmalaya, Ciamis, Banjar)", "network": "GSM / 4G / 5G"},
    "082263": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Cirebon, Indramayu, Majalengka)", "network": "GSM / 4G / 5G"},
    "082264": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Purwakarta, Subang, Karawang)", "network": "GSM / 4G / 5G"},
    "08221": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten (Jakarta, Tangerang)", "network": "GSM / 4G / 5G"},
    "08222": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Tengah & DI Yogyakarta (Semarang, Solo, Jogja)", "network": "GSM / 4G / 5G"},
    "08223": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Jawa Timur & Bali (Surabaya, Malang, Denpasar)", "network": "GSM / 4G / 5G"},
    "08224": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Sulawesi & Maluku (Makassar, Manado, Kendari)", "network": "GSM / 4G / 5G"},
    "08225": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Kalimantan (Balikpapan, Banjarmasin, Samarinda)", "network": "GSM / 4G / 5G"},
    "08227": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Selatan (Palembang, Lampung, Bengkulu)", "network": "GSM / 4G / 5G"},
    "08228": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Tengah (Pekanbaru, Padang, Batam)", "network": "GSM / 4G / 5G"},
    "08229": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Sulawesi & Indonesia Timur", "network": "GSM / 4G / 5G"},
    "0822": {"carrier": "Telkomsel", "brand": "simPATI / Loop", "mcc": "510", "mnc": "10", "region": "Regional Barat & Nasional", "network": "GSM / 4G / 5G"},

    # --- Kartu As (0823, 0852, 0853) ---
    "08231": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten", "network": "GSM / 4G / 5G"},
    "08232": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Tengah & DI Yogyakarta", "network": "GSM / 4G / 5G"},
    "08233": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Timur & Madura", "network": "GSM / 4G / 5G"},
    "0823": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa & Luar Jawa", "network": "GSM / 4G / 5G"},

    "08521": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jabodetabek & Banten", "network": "GSM / 4G / 5G"},
    "08522": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Barat (Bandung, Sukabumi, Cirebon)", "network": "GSM / 4G / 5G"},
    "08523": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Timur & Bali", "network": "GSM / 4G / 5G"},
    "08526": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Utara & Riau", "network": "GSM / 4G / 5G"},
    "08527": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Selatan (Palembang, Lampung)", "network": "GSM / 4G / 5G"},
    "0852": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera, Kalimantan & Jawa", "network": "GSM / 4G / 5G"},

    "08531": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Barat & Banten", "network": "GSM / 4G / 5G"},
    "08533": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Timur & Nusa Tenggara", "network": "GSM / 4G / 5G"},
    "08535": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Kalimantan (Pontianak, Banjarmasin)", "network": "GSM / 4G / 5G"},
    "08536": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Utara (Medan, Aceh)", "network": "GSM / 4G / 5G"},
    "08537": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Sumatera Bagian Selatan", "network": "GSM / 4G / 5G"},
    "0853": {"carrier": "Telkomsel", "brand": "Kartu As", "mcc": "510", "mnc": "10", "region": "Jawa Timur / Bali / Nusa Tenggara", "network": "GSM / 4G / 5G"},

    # --- by.U (Digital Telkomsel) (0851) ---
    "08515": {"carrier": "Telkomsel", "brand": "by.U (Digital Telco Telkomsel)", "mcc": "510", "mnc": "10", "region": "Nasional (Digital Telco)", "network": "4G LTE / 5G"},
    "08516": {"carrier": "Telkomsel", "brand": "by.U (Digital Telco Telkomsel)", "mcc": "510", "mnc": "10", "region": "Nasional (Digital Telco)", "network": "4G LTE / 5G"},
    "08517": {"carrier": "Telkomsel", "brand": "by.U (Digital Telco Telkomsel)", "mcc": "510", "mnc": "10", "region": "Nasional (Digital Telco)", "network": "4G LTE / 5G"},
    "0851": {"carrier": "Telkomsel", "brand": "by.U / Telkomsel Digital", "mcc": "510", "mnc": "10", "region": "Nasional (Digital Telco)", "network": "4G LTE / 5G"},

    # ============================================================
    # 2. INDOSAT OOREDOO HUTCHISON (MCC: 510, MNC: 01 / 89)
    # ============================================================
    "0814": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Indosat Broadband M2", "mcc": "510", "mnc": "01", "region": "Nasional (Data Network)", "network": "Broadband / GSM"},
    "08151": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek & Banten (Jakarta)", "network": "GSM / 4G / 5G"},
    "08152": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jawa Barat (Bandung, Bogor, Cirebon)", "network": "GSM / 4G / 5G"},
    "08153": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jawa Tengah & DIY (Semarang, Solo, Jogja)", "network": "GSM / 4G / 5G"},
    "08154": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jawa Timur & Madura (Surabaya, Malang)", "network": "GSM / 4G / 5G"},
    "0815": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix / Mentari / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek & Jawa", "network": "GSM / 4G / 5G"},

    "0816": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix Postpaid / IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek & Nasional", "network": "GSM / 4G / 5G"},
    "0855": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Matrix Auto / IM3 Postpaid", "mcc": "510", "mnc": "01", "region": "Jabodetabek (Pasca Bayar)", "network": "GSM / 4G / 5G"},

    # --- IM3 (0856 & 0857) ---
    "08561": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek & Banten (Jakarta, Tangerang)", "network": "GSM / 4G / 5G"},
    "08562": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jawa Barat (Bandung, Cimahi, Garut)", "network": "GSM / 4G / 5G"},
    "08563": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jawa Timur (Surabaya, Malang, Kediri)", "network": "GSM / 4G / 5G"},
    "08564": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jawa Tengah & DI Yogyakarta (Semarang, Solo, Jogja)", "network": "GSM / 4G / 5G"},
    "08565": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Kalimantan (Balikpapan, Pontianak)", "network": "GSM / 4G / 5G"},
    "08566": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Sumatera Bagian Utara (Medan, Aceh)", "network": "GSM / 4G / 5G"},
    "0856": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3", "mcc": "510", "mnc": "01", "region": "Jabodetabek, Jawa Barat & Jawa Tengah", "network": "GSM / 4G / 5G"},

    "08571": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jabodetabek & Banten (Jakarta, Bogor, Depok, Tangerang, Bekasi)", "network": "GSM / 4G / 5G"},
    "08572": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Barat (Bandung, Sukabumi, Karawang)", "network": "GSM / 4G / 5G"},
    "08573": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Timur & Bali (Surabaya, Malang, Denpasar)", "network": "GSM / 4G / 5G"},
    "08574": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Tengah & DIY (Semarang, Solo, Magelang)", "network": "GSM / 4G / 5G"},
    "08575": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Kalimantan (Samarinda, Banjarmasin)", "network": "GSM / 4G / 5G"},
    "08576": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Sumatera Bagian Utara & Tengah (Medan, Pekanbaru, Padang)", "network": "GSM / 4G / 5G"},
    "08577": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jabodetabek (Jakarta & Sekitarnya)", "network": "GSM / 4G / 5G"},
    "08578": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Barat & Banten", "network": "GSM / 4G / 5G"},
    "0857": {"carrier": "Indosat Ooredoo Hutchison", "brand": "IM3 Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Barat, Jawa Tengah & Nasional", "network": "GSM / 4G / 5G"},

    "0858": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Mentari Ooredoo", "mcc": "510", "mnc": "01", "region": "Jawa Timur, Jawa Tengah & Jabodetabek", "network": "GSM / 4G / 5G"},

    # --- Tri (3) Indonesia (0895 - 0899) ---
    "0895": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jabodetabek, Jawa & Nasional", "network": "GSM / 4G / 5G"},
    "08960": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jabodetabek (Jakarta, Depok, Tangerang)", "network": "GSM / 4G / 5G"},
    "08961": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Barat (Bandung, Bekasi)", "network": "GSM / 4G / 5G"},
    "08962": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Barat & Banten", "network": "GSM / 4G / 5G"},
    "08963": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Tengah & DIY", "network": "GSM / 4G / 5G"},
    "08964": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Timur (Surabaya, Malang)", "network": "GSM / 4G / 5G"},
    "0896": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Barat & Jawa Tengah", "network": "GSM / 4G / 5G"},
    "0897": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Sumatera & Jawa Barat", "network": "GSM / 4G / 5G"},
    "0898": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jawa Timur, Bali & Lombok", "network": "GSM / 4G / 5G"},
    "0899": {"carrier": "Indosat Ooredoo Hutchison", "brand": "Tri (3) Indonesia", "mcc": "510", "mnc": "89", "region": "Jabodetabek & Luar Jawa", "network": "GSM / 4G / 5G"},

    # ============================================================
    # 3. XL AXIATA (MCC: 510, MNC: 11 / 08)
    # ============================================================
    "0817": {"carrier": "XL Axiata", "brand": "XL Prioritas (Postpaid)", "mcc": "510", "mnc": "11", "region": "Jabodetabek & Jawa", "network": "GSM / 4G / 5G"},
    "0818": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek & Jawa Barat", "network": "GSM / 4G / 5G"},
    "0819": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jawa, Bali & Nusa Tenggara", "network": "GSM / 4G / 5G"},
    "0859": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Sumatera & Jawa Timur", "network": "GSM / 4G / 5G"},
    "0877": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek, Jawa Barat & Jawa Tengah", "network": "GSM / 4G / 5G"},
    "0878": {"carrier": "XL Axiata", "brand": "XL Prabayar", "mcc": "510", "mnc": "11", "region": "Jabodetabek, Banten & Jawa Timur", "network": "GSM / 4G / 5G"},

    # --- AXIS Telecom (0831 - 0838) ---
    "0831": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Sumatera & Jawa Barat", "network": "GSM / 4G / 5G"},
    "0832": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jawa Tengah & DI Yogyakarta", "network": "GSM / 4G / 5G"},
    "0833": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jawa Timur & Bali", "network": "GSM / 4G / 5G"},
    "0838": {"carrier": "XL Axiata", "brand": "AXIS Telecom", "mcc": "510", "mnc": "08", "region": "Jabodetabek & Banten", "network": "GSM / 4G / 5G"},

    # ============================================================
    # 4. SMARTFREN (MCC: 510, MNC: 09 / 28)
    # ============================================================
    "0881": {"carrier": "Smartfren", "brand": "Smartfren 4G / VoLTE", "mcc": "510", "mnc": "09", "region": "Jabodetabek & Jawa", "network": "4G LTE / 5G"},
    "0882": {"carrier": "Smartfren", "brand": "Smartfren 4G / VoLTE", "mcc": "510", "mnc": "09", "region": "Jawa Barat & Banten (Bandung, Serang)", "network": "4G LTE / 5G"},
    "0883": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Sumatera Bagian Tengah & Riau", "network": "4G LTE / 5G"},
    "0884": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Kalimantan & Sulawesi", "network": "4G LTE / 5G"},
    "0885": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Bali & Nusa Tenggara", "network": "4G LTE / 5G"},
    "0886": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Jawa Tengah & DIY (Semarang, Solo)", "network": "4G LTE / 5G"},
    "0887": {"carrier": "Smartfren", "brand": "Smartfren 4G / eSIM", "mcc": "510", "mnc": "09", "region": "Jawa Tengah & DIY", "network": "4G LTE / 5G"},
    "0888": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Jawa Timur & Madura (Surabaya, Malang)", "network": "4G LTE / 5G"},
    "0889": {"carrier": "Smartfren", "brand": "Smartfren 4G", "mcc": "510", "mnc": "09", "region": "Nasional (Data Roaming / 4G)", "network": "4G LTE / 5G"},

    # ============================================================
    # 5. SAMPOERNA TELECOM / NET1 (MNC: 07)
    # ============================================================
    "0828": {"carrier": "Sampoerna Telecom (Net1)", "brand": "Net1 Indonesia 450MHz", "mcc": "510", "mnc": "07", "region": "Rural / 4G LTE 450MHz", "network": "LTE 450"}
}

class PhoneOSINT(BaseOSINTModule):
    name: str = "Phone Intelligence Module"
    module_id: str = "phone_osint"
    description: str = "Validasi ITU-T E.164, granular offline HLR database, passive WhatsApp business probing, threat intel breach links, dan automated OSINT dorking."
    version: str = "2.4.1"
    priority: int = 1
    target_type: str = "phone"

    def _lookup_granular_hlr(self, national_number: str) -> Dict[str, Any]:
        """
        Database HLR Offline Indonesia Granular:
        Mencocokkan prefix nomor telepon dari 6 digit, 5 digit, hingga 4 digit.
        """
        clean_num = national_number.strip()
        if not clean_num.startswith("0"):
            clean_num = "0" + clean_num

        # 1. Cek prefix 6 digit (Paling Spesifik)
        if len(clean_num) >= 6 and clean_num[:6] in INDONESIA_HLR_GRANULAR_DB:
            info = INDONESIA_HLR_GRANULAR_DB[clean_num[:6]]
            return {
                "matched": True,
                "match_level": "Granular (6-Digit Prefix)",
                "prefix": clean_num[:6],
                "carrier": info["carrier"],
                "card_brand": info["brand"],
                "mcc": info["mcc"],
                "mnc": info["mnc"],
                "hlr_region": info["region"],
                "network_type": info["network"]
            }

        # 2. Cek prefix 5 digit
        if len(clean_num) >= 5 and clean_num[:5] in INDONESIA_HLR_GRANULAR_DB:
            info = INDONESIA_HLR_GRANULAR_DB[clean_num[:5]]
            return {
                "matched": True,
                "match_level": "Sub-Regional (5-Digit Prefix)",
                "prefix": clean_num[:5],
                "carrier": info["carrier"],
                "card_brand": info["brand"],
                "mcc": info["mcc"],
                "mnc": info["mnc"],
                "hlr_region": info["region"],
                "network_type": info["network"]
            }

        # 3. Cek prefix 4 digit
        if len(clean_num) >= 4 and clean_num[:4] in INDONESIA_HLR_GRANULAR_DB:
            info = INDONESIA_HLR_GRANULAR_DB[clean_num[:4]]
            return {
                "matched": True,
                "match_level": "Regional (4-Digit Prefix)",
                "prefix": clean_num[:4],
                "carrier": info["carrier"],
                "card_brand": info["brand"],
                "mcc": info["mcc"],
                "mnc": info["mnc"],
                "hlr_region": info["region"],
                "network_type": info["network"]
            }

        return {
            "matched": False,
            "match_level": "Generic / Unmatched",
            "prefix": clean_num[:4] if len(clean_num) >= 4 else clean_num,
            "carrier": "Operator Seluler Indonesia",
            "card_brand": "Unknown Prepaid/Postpaid",
            "mcc": "510",
            "mnc": "Unknown",
            "hlr_region": "Indonesia (Nasional)",
            "network_type": "Cellular Network"
        }

    def _generate_permutations(self, parsed_obj: phonenumbers.PhoneNumber) -> Dict[str, str]:
        """Menghasilkan variasi format nomor standar telekomunikasi dan dorking"""
        e164 = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.NATIONAL)
        rfc3966 = phonenumbers.format_number(parsed_obj, phonenumbers.PhoneNumberFormat.RFC3966)
        
        raw_e164 = re.sub(r'[^0-9]', '', e164)
        raw_nat = re.sub(r'[^0-9]', '', nat)

        nat_spaced = " ".join([raw_nat[:4], raw_nat[4:8], raw_nat[8:]]).strip()
        nat_hyphen = "-".join([raw_nat[:4], raw_nat[4:8], raw_nat[8:]]).strip("-")

        return {
            "e164": e164,
            "international": intl,
            "national": nat,
            "rfc3966": rfc3966,
            "raw_e164_digits": raw_e164,
            "raw_national_digits": raw_nat,
            "national_spaced": nat_spaced,
            "national_hyphenated": nat_hyphen
        }

    async def _verify_whatsapp_passive(self, raw_e164: str) -> Dict[str, Any]:
        """
        Verifikasi Pasif Status WhatsApp & Akun Bisnis via HTTP probing ke endpoint WhatsApp.
        """
        wa_info = {
            "status": "Available / Unconfirmed",
            "is_business": False,
            "direct_chat_link": f"https://wa.me/{raw_e164}",
            "api_endpoint": f"https://api.whatsapp.com/send/?phone={raw_e164}&text&type=phone_number&app_absent=0",
            "status_badge": "Direct Link Available"
        }

        if not self.async_client:
            return wa_info

        try:
            custom_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
            }
            status, html, _ = await self.async_client.get(wa_info["api_endpoint"], headers=custom_headers, timeout=6)
            if status == 200:
                html_lower = html.lower()
                if any(phrase in html_lower for phrase in ["chat on whatsapp", "buka whatsapp", "send message", "continue to chat"]):
                    wa_info["status"] = "Active WhatsApp Account [OK]"
                    wa_info["status_badge"] = "Terdaftar Aktif di WhatsApp"

                if any(tag in html_lower for tag in ["business account", "akun bisnis", "whatsapp business", "official business"]):
                    wa_info["is_business"] = True
                    wa_info["status_badge"] = "Akun WhatsApp Business Terverifikasi [BIZ]"
        except Exception as e:
            self.logger.debug(f"Passive WhatsApp probing warning: {e}")

        return wa_info

    def _generate_threat_intel_links(self, raw_e164: str, raw_nat: str) -> List[Dict[str, str]]:
        """Menghasilkan direct link investigasi ke platform Threat Intelligence & Breach Engines"""
        return [
            {
                "platform": "Intelligence X (IntelX)",
                "category": "Darknet & Breach Records",
                "url": f"https://intelx.io/?s={urllib.parse.quote(raw_e164)}",
                "description": "Pencarian kebocoran kredensial, paste dumps, dan database dark web"
            },
            {
                "platform": "DeHashed Search Engine",
                "category": "Compromised Database Search",
                "url": f"https://www.dehashed.com/search?query={urllib.parse.quote(raw_e164)}",
                "description": "Pencarian jejak akun dan database breach global"
            },
            {
                "platform": "LeakCheck Web Lookup",
                "category": "Public Breach Correlation",
                "url": f"https://leakcheck.io/search?type=phone&query={urllib.parse.quote(raw_e164)}",
                "description": "Verifikasi kebocoran nomor telepon pada database leak publik"
            },
            {
                "platform": "Kredibel.co.id (Indonesia)",
                "category": "Fraud & Scam Directory",
                "url": f"https://www.kredibel.co.id/search?q={raw_nat}",
                "description": "Cek rekam jejak laporan penipuan transaksi dan rekening perbankan"
            },
            {
                "platform": "Tellows Indonesia",
                "category": "Spam Caller & Community Score",
                "url": f"https://www.tellows.id/num/{raw_nat}",
                "description": "Evaluasi skor spam, tipe panggilan (telemarketing/penipuan)"
            },
            {
                "platform": "CekRekening.id (Kominfo)",
                "category": "Official Government Scam Check",
                "url": "https://cekrekening.id/",
                "description": "Portal resmi Kominfo untuk verifikasi nomor & kontak penipuan"
            }
        ]

    def _generate_osint_dorks(self, perms: Dict[str, str]) -> List[Dict[str, str]]:
        """Menghasilkan daftar link Google & DuckDuckGo Dorking siap klik untuk penelusuran jejak digital"""
        query_variants = [
            f'"{perms["national"]}"',
            f'"{perms["national_hyphenated"]}"',
            f'"{perms["e164"]}"',
            f'"{perms["raw_national_digits"]}"'
        ]
        base_or_query = " OR ".join(list(set(query_variants)))

        dork_templates = [
            {
                "category": "Dokumen Publik & Arsip (.PDF / .XLSX / .DOCX)",
                "description": "Mencari daftar kontak, absensi, SK pengangkatan, atau dokumen resmi",
                "dork": f'(filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv) ({base_or_query})'
            },
            {
                "category": "Marketplace & Jual Beli Online",
                "description": "Mencari jejak lapak di Tokopedia, Shopee, OLX, Bukalapak, Kaskus",
                "dork": f'(site:tokopedia.com OR site:shopee.co.id OR site:olx.co.id OR site:bukalapak.com OR site:kaskus.co.id) ({base_or_query})'
            },
            {
                "category": "Media Sosial & Direktori Profil",
                "description": "Mencari bio, postingan kontak di Instagram, Facebook, LinkedIn, Twitter/X, TikTok",
                "dork": f'(site:instagram.com OR site:facebook.com OR site:linkedin.com OR site:twitter.com OR site:tiktok.com) ({base_or_query})'
            },
            {
                "category": "Paste Sites & Teks Bocor",
                "description": "Mencari kebocoran teks publik di Pastebin, Ghostbin, JustPaste, Rentry",
                "dork": f'(site:pastebin.com OR site:ghostbin.com OR site:justpaste.it OR site:rentry.co) ({base_or_query})'
            },
            {
                "category": "Reputasi Nomor & Laporan Penipuan",
                "description": "Cek rekam jejak spam dan penipuan di Kredibel, Tellows, CekRekening, Lapor.go.id",
                "dork": f'(site:kredibel.co.id OR site:tellows.id OR site:cekrekening.id OR site:lapor.go.id) ("{perms["national"]}" OR "{perms["raw_national_digits"]}")'
            }
        ]

        dork_list = []
        for d in dork_templates:
            encoded_q = urllib.parse.quote(d["dork"])
            google_url = f"https://www.google.com/search?q={encoded_q}"
            duckduckgo_url = f"https://duckduckgo.com/?q={encoded_q}"
            dork_list.append({
                "category": d["category"],
                "description": d["description"],
                "dork_query": d["dork"],
                "google_search_url": google_url,
                "duckduckgo_search_url": duckduckgo_url
            })

        return dork_list

    def _generate_endpoint_links(self, perms: Dict[str, str], country_code: int) -> Dict[str, str]:
        """Menghasilkan direct deep links ke platform perpesanan dan direktori verifikasi"""
        clean_e164 = perms["raw_e164_digits"]
        clean_nat = perms["raw_national_digits"]

        return {
            "whatsapp_direct": f"https://wa.me/{clean_e164}",
            "whatsapp_api": f"https://api.whatsapp.com/send/?phone={clean_e164}&text&type=phone_number&app_absent=0",
            "telegram_direct": f"https://t.me/+{clean_e164}",
            "truecaller_search": f"https://www.truecaller.com/search/{'id' if country_code == 62 else 'global'}/{clean_nat}",
            "syncme_search": f"https://sync.me/search/?number=+{clean_e164}"
        }

    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            # 1. Parsing Standar ITU-T E.164
            default_reg = "ID" if (target.strip().startswith("0") or target.strip().startswith("8")) else None
            parsed = phonenumbers.parse(target, default_reg)
            
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)

            if not is_possible:
                return self.error_response(f"Format nomor '{target}' tidak mungkin valid menurut standar telekomunikasi dunia.")

            # 2. Ekstraksi Permutasi Format
            permutations = self._generate_permutations(parsed)
            
            # 3. Klasifikasi Tipe Saluran (Line Type)
            num_type_code = phonenumbers.number_type(parsed)
            num_types_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile / Seluler (GSM/LTE/5G)",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line / PSTN (Telepon Rumah/Kantor)",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line atau Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free (Bebas Pulsa)",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate (Layanan Berbayar Khusus)",
                phonenumbers.PhoneNumberType.VOIP: "VoIP (Voice over IP / Virtual Number)",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "UAN (Universal Access Number)"
            }
            line_type = num_types_map.get(num_type_code, "Unknown / Specialized Number")

            # 4. Deteksi Zona Waktu & Metadata Geografis Lengkap
            raw_timezones = list(timezone.time_zones_for_number(parsed))
            formatted_timezones = []
            for tz in raw_timezones:
                if "Jakarta" in tz:
                    formatted_timezones.append(f"{tz} (WIB - UTC+7 / Waktu Indonesia Barat)")
                elif "Makassar" in tz or "Ujung_Pandang" in tz:
                    formatted_timezones.append(f"{tz} (WITA - UTC+8 / Waktu Indonesia Tengah)")
                elif "Jayapura" in tz:
                    formatted_timezones.append(f"{tz} (WIT - UTC+9 / Waktu Indonesia Timur)")
                else:
                    formatted_timezones.append(tz)

            itu_carrier = carrier.name_for_number(parsed, "id") or carrier.name_for_number(parsed, "en") or "Unknown"
            country_name = geocoder.country_name_for_number(parsed, "id") or geocoder.country_name_for_number(parsed, "en") or "Indonesia"
            location_desc = geocoder.description_for_number(parsed, "id") or geocoder.description_for_number(parsed, "en") or ""

            # 5. Database Offline HLR Granular (4-6 digit)
            hlr_intelligence = {}
            if parsed.country_code == 62:
                hlr_intelligence = self._lookup_granular_hlr(str(parsed.national_number))
                carrier_display = hlr_intelligence.get("carrier", itu_carrier)
                card_brand = hlr_intelligence.get("card_brand", "Unknown Prepaid/Postpaid")
            else:
                carrier_display = itu_carrier
                card_brand = "International Mobile Carrier"
                hlr_intelligence = {
                    "matched": False,
                    "match_level": "International ITU-T",
                    "carrier": itu_carrier,
                    "card_brand": card_brand,
                    "mcc": str(parsed.country_code),
                    "mnc": "N/A",
                    "hlr_region": location_desc or country_name,
                    "network_type": line_type
                }

            # 6. Verifikasi Pasif Status WhatsApp & Akun Bisnis
            whatsapp_intel = await self._verify_whatsapp_passive(permutations["raw_e164_digits"])

            # 7. Endpoint Verification Links & Threat Intel Links
            endpoint_links = self._generate_endpoint_links(permutations, parsed.country_code)
            threat_intel_links = self._generate_threat_intel_links(permutations["raw_e164_digits"], permutations["raw_national_digits"])

            # 8. Automated OSINT Google Dorking List
            osint_dorks = self._generate_osint_dorks(permutations)

            data = {
                "validation": {
                    "is_valid_e164": is_valid,
                    "is_possible_number": is_possible,
                    "status_label": "VALID [ITU-T E.164]" if is_valid else "POSSIBLE / UNCONFIRMED"
                },
                "formatting": permutations,
                "telecom_meta": {
                    "country_code": parsed.country_code,
                    "national_number": str(parsed.national_number),
                    "line_type": line_type,
                    "country": country_name,
                    "location_description": location_desc or hlr_intelligence.get("hlr_region", "Indonesia"),
                    "timezones": formatted_timezones,
                    "raw_timezones": raw_timezones
                },
                "hlr_carrier_intelligence": {
                    "carrier_name": carrier_display,
                    "card_brand": card_brand,
                    "prefix": hlr_intelligence.get("prefix", ""),
                    "mcc": hlr_intelligence.get("mcc", "510"),
                    "mnc": hlr_intelligence.get("mnc", "N/A"),
                    "hlr_region": hlr_intelligence.get("hlr_region", location_desc or "Nasional"),
                    "match_level": hlr_intelligence.get("match_level", "Regional"),
                    "network_technology": hlr_intelligence.get("network_type", "GSM/LTE/5G"),
                    "source": "Granular Offline HLR Database (4-6 Digit) & ITU-T Registry"
                },
                "whatsapp_intelligence": whatsapp_intel,
                "endpoint_links": endpoint_links,
                "threat_intel_links": threat_intel_links,
                "osint_dorks": osint_dorks,
                # Backward compatibility
                "e164": permutations["e164"],
                "international": permutations["international"],
                "national": permutations["national"],
                "carrier": carrier_display,
                "country": country_name,
                "type": line_type,
                "valid": is_valid
            }

            return self.success_response(data, f"Analisis Intelijen Nomor {permutations['e164']} Berhasil.")
        except Exception as e:
            return self.error_response(f"Gagal memproses nomor telepon '{target}': {e}")
