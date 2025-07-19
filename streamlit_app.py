import time
from datetime import timedelta
import streamlit as st
import requests
import pandas as pd


API_URL = "http://127.0.0.1:8000"


# Session state başlatma
if 'token' not in st.session_state:
    st.session_state['token'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'role' not in st.session_state:
    st.session_state['role'] = False
if 'page' not in st.session_state:
    st.session_state['page'] = "login"  # admin, member

def navigate_to(page_name):
    """Sayfa değiştirmek için kullanılır."""
    st.session_state.page = page_name
    st.rerun()

def validate_token_and_get_user(token):
    """Verilen token'ı doğrular ve kullanıcı bilgilerini getirir."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{API_URL}/users/me", headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            st.session_state.logged_in = True
            st.session_state.username = user_data.get("username")
            st.session_state.token = token
            st.session_state.role = user_data.get("is_admin")
            st.session_state.page = "admin" if st.session_state.role else "member"
            return True
        else:
            # Token geçersizse veya süresi dolmuşsa session state'i temizle
            st.session_state.logged_in = False
            st.session_state.token = None
            st.session_state.username = None
            st.session_state.role = False
            st.session_state.page = "login"
            return False
    except requests.exceptions.ConnectionError:
        st.error("API sunucusuna bağlanılamıyor.")
        return False
    except Exception as e:
        st.error("Oturum doğrulanırken bir hata oluştu: ",e)
        return False



def login(username, password):

    try:
        response = requests.post(f"{API_URL}/users/token", data={"username": username, "password": password})


        if response.status_code == 200:
            st.session_state.token=response.json()['access_token']
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            
            user_response = requests.get(f"{API_URL}/users/me", headers=headers)
            if user_response.status_code == 200:
                st.session_state.user = user_response.json()
                st.session_state.username = user_response.json()['username']
                st.session_state.role = user_response.json()['is_admin']
                st.session_state.logged_in = True
                # Role göre sayfa belirle
                if st.session_state.role:
                    navigate_to("admin")
                else:
                    navigate_to("member")
                return True

        elif response.status_code == 401:
            st.sidebar.write("Token alma başarısız - 401 hatası")
            st.error("Giriş başarısız. Lütfen girdiğiniz bilgileri kontrol edin.")
        else:
            st.sidebar.write(f"Beklenmeyen token response: {response.status_code}")
        return False
    except requests.exceptions.ConnectionError:
        st.sidebar.write("API bağlantı hatası")
        st.error("API Sunucusuna bağlanılamıyor")
        return False
    except Exception as e:
        st.sidebar.write(f"Genel hata: {e}")
        st.error(f"Bir hata oluştu: {e}")
        return False


def get_all_users(token):
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response= requests.get(f"{API_URL}/admin/get_users", headers=headers)
        if response.status_code==200:
            return response.json()
        else:
            st.error(f"Kullanıcıları getirirken bir hata oluştu: {response.json().get('detail')}")
            return None
    except requests.exceptions.ConnectionError:
        st.error("API Sunucusuna bağlanılamıyor")
        return None

def add_user(token, data:dict):
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.post(f"{API_URL}/admin/create_user", headers=headers, json=data)
            if response.status_code==200:
                st.success(f"{data.get('full_name')} adlı kullanıcı başarıyla eklendi!")

        except requests.exceptions.ConnectionError:
            st.error("API sunucusuna bağlanılamıyor")

def delete_user(token, username):
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.delete(f"{API_URL}/admin/delete_user/{username}", headers=headers)
        if response.status_code==200:
            st.success( f"{username} adlı kullanıcı başarıyla silindi!")
        else:
            st.error("Kullanıcı silinemedi")
    except requests.exceptions.ConnectionError:
        st.error("API sunucusuna bağlanılamadı")



def show_login_page():
    tab1, tab2 = st.tabs(["👤 Kullanıcı Girişi (Yüz Tanıma)", "🔑 Admin Girişi"])

    with tab1:
        st.header("Üye Giriş Paneli")
        with st.form("member_login_form", clear_on_submit=True):
            username = st.text_input("Kullanıcı Adı")
            password = st.text_input("Şifre", type="password")
            submitted = st.form_submit_button("Giriş Yap")
            if submitted:
                login(username, password)



    with tab2:
        st.header("Admin Giriş Paneli")
        with st.form("admin_login_form", clear_on_submit=True):
            username = st.text_input("Kullanıcı Adı")
            password = st.text_input("Şifre", type= "password")
            submitted = st.form_submit_button("Giriş Yap")
            if submitted:
                login(username, password)


def logout():
    # Session state'i temizle
    st.session_state.logged_in = False
    st.session_state.token = None
    st.session_state.username = None
    st.session_state.role = False
    st.session_state.page = "login"
    
    # Başarı mesajı göster
    st.success("Başarıyla çıkış yapıldı!")
    
    # Sayfayı yenile
    st.rerun()

def admin_panel():
    st.header("Admin Paneli")
    st.sidebar.header("Admin Paneli")
    
    # Çıkış butonu
    if st.sidebar.button("Çıkış Yap", key="logout_button"):
        logout()
        return  # Fonksiyondan çık
    st.subheader("Yeni Kullanıcı Ekle")
    with st.form("new_user_form", clear_on_submit=True):
        full_name = st.text_input("Ad Soyad")
        username = st.text_input("Yeni Kullanıcı Adı")
        password = st.text_input("Şifre", type="password")
        is_admin = st.checkbox("Admin yetkisi verilsin mi ?")
        submitted = st.form_submit_button("Kullanıcıyı Ekle")
        if submitted:
            data = {
                "full_name": full_name,
                "username": username,
                "is_admin": is_admin,
                "password":password }
            add_user(st.session_state.token, data)

        else:
            st.warning("Lütfen tüm alanları eksiksiz doldurun.")
    st.subheader("Kullanıcı Listesi")

    st.markdown("---")
    header_col1, header_col2, header_col3, header_col4 = st.columns([2, 1, 2, 1])
    with header_col1:
        st.markdown("<h4 style='text-align: left; color: #4682B4;'>Kullanıcı Adı</h4>", unsafe_allow_html=True)
    with header_col2:
        st.markdown("<h4 style='text-align: left; color: #4682B4;'>Tam Adı</h4>", unsafe_allow_html=True)
    with header_col3:
        st.markdown("<h4 style='text-align: left; color: #4682B4;'>Admin Yetkisi</h4>", unsafe_allow_html=True)
    with header_col4:
        st.markdown("<h4 style='text-align: left; color: #4682B4;'>İşlemler</h4>", unsafe_allow_html=True)
    st.markdown("---")


    try:
        users=get_all_users(st.session_state.token)
        for user in users:
            col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
            with col1:
                st.write(user['username'])
            with col2:
                st.write(user['full_name'])
            with col3:
                if user['is_admin']:
                    st.write("Admin")
                else:
                    st.write("Üye")
            with col4:
                if user['is_admin'] == False:  # Admin kendini silemesin
                    if st.button("Sil", key=f"delete_{user['username']}"):
                        delete_user(st.session_state.token, user['username'])

    except requests.exceptions.ConnectionError:
        st.error("API sunucusuna bağlanılamıyor.")


def member_panel():
    st.header("Üye Paneli")
    response = requests.get(f"{API_URL}/users/me", headers={"Authorization": f"Bearer {st.session_state.token}"})
    user_data = response.json()
    st.write("Hoşgeldin ", user_data.get("full_name"))




st.set_page_config(page_title="FaceSecure")
st.title("FaceSecure")

# Ana uygulama akışı
def main():
    # Session state kontrolü
    if not st.session_state.logged_in or st.session_state.page == "login":
        show_login_page()
    else:
        # Oturum açıksa, doğru sayfayı göster
        if st.session_state.page == "member":
            member_panel()
        elif st.session_state.page == "admin":
            admin_panel()

# Ana fonksiyonu çağır
main()















