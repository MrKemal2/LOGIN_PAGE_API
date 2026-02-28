# Login Page API

Login Page API, FastAPI tabanlı güçlü bir arka uç (backend) ve Streamlit tabanlı kullanıcı dostu bir ön uç (frontend) ile geliştirilmiş, rol tabanlı erişim kontrolü sunan bir kimlik doğrulama sistemidir. 

Proje, güvenli JWT (JSON Web Token) kimlik doğrulaması kullanarak yönetici (Admin) ve normal kullanıcı (Üye) yetkilendirmelerini birbirinden ayırır ve MongoDB veritabanı entegrasyonu ile kullanıcı yönetimini sağlar.

##  Özellikler

* **Güvenli Kimlik Doğrulama:** JSON Web Token (JWT) kullanılarak oturum yönetimi sağlanır.
* **Şifre Güvenliği:** Kullanıcı şifreleri `bcrypt` algoritması kullanılarak veritabanında şifrelenmiş (hash) olarak saklanır.
* **Rol Tabanlı Erişim:** Admin ve Üye olmak üzere iki farklı rol bulunur. Yetkilendirme gerektiren işlemlerde rol kontrolleri yapılır.
* **Yönetici Paneli (Admin):** * Sistemdeki tüm kullanıcıları görüntüleme.
    * Sisteme yeni yönetici veya normal kullanıcı ekleme.
    * Mevcut kullanıcıları sistemden silme.
* **Üye Paneli:** Başarıyla giriş yapan normal kullanıcılar için kişiselleştirilmiş karşılama ekranı.
* **Modern Arayüz:** Streamlit sayesinde hızlı, duyarlı ve etkileşimli bir web arayüzü sunulur.

##  Kullanılan Teknolojiler

* **Backend:** Python, FastAPI
* **Frontend:** Streamlit, Pandas, Requests
* **Veritabanı:** MongoDB (PyMongo)
* **Güvenlik:** PyJWT, Passlib (Bcrypt)

## 📁 Proje Yapısı

```text
LOGIN_PAGE_API/
├── main.py              # FastAPI uygulamasının ana başlangıç noktası
├── database.py          # MongoDB bağlantı ayarları ve veritabanı fonksiyonları
├── security.py          # Şifre hashleme, JWT token oluşturma ve doğrulama
├── schemas.py           # Pydantic modelleri (Veri doğrulama şablonları)
├── routers/             # API yönlendiricileri (Endpoints)
│   ├── admin.py         # Yönetici işlemleri için API yolları
│   └── users.py         # Kullanıcı girişi ve token işlemleri için API yolları
└── streamlit_app.py     # Streamlit ile hazırlanan frontend arayüzü
```

## ⚙️ Kurulum ve Çalıştırma Adımları

Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları takip edebilirsiniz:

### 1. Gereksinimleri Yükleyin

Python ortamınızda gerekli kütüphaneleri yüklemek için terminalde şu komutu çalıştırın:

``` bash
pip install fastapi uvicorn pymongo streamlit requests pandas passlib[bcrypt] pyjwt pydantic
```

### 2. Veritabanını Hazırlayın

   Sisteminizde MongoDB'nin kurulu ve arka planda çalışıyor olduğundan emin olun.

   Proje varsayılan olarak `mongodb://localhost:27017/` adresine bağlanmaya çalışır ve denemeFaceSecure adlı bir veritabanı kullanır.

### 3. API (Backend) Sunucusunu Başlatın
   
   Uygulamanın bulunduğu dizinde bir terminal açın ve FastAPI sunucusunu Uvicorn ile başlatın:
   

```bash
uvicorn main:app --reload
```

Sunucu varsayılan olarak `http://127.0.0.1:8000` adresinde çalışmaya başlayacaktır.
### 4. Arayüz (Frontend) Sunucusunu Başlatın

Yeni bir terminal sekmesi açın ve Streamlit uygulamasını başlatın:
Bash

```streamlit run streamlit_app.py```

Bu komut, tarayıcınızda uygulama arayüzünü otomatik olarak açacaktır.
🔗 API Uç Noktaları (Endpoints)

FastAPI otomatik dokümantasyon sağlar. Sunucu çalışırken `http://127.0.0.1:8000/docs` adresine giderek tüm API yollarını test edebilirsiniz.

Kullanıcı (Users) Yönlendirmeleri:

    POST /users/token: Kullanıcı adı ve şifre ile JWT erişim belirteci (token) alır.

    GET /users/me: Token kullanarak giriş yapmış mevcut kullanıcının bilgilerini getirir.

Yönetici (Admin) Yönlendirmeleri:

    GET /admin/get_users: Sistemdeki tüm kullanıcıların listesini getirir.

    POST /admin/create_user: Yeni bir kullanıcı oluşturur (Sadece admin erişebilir).

    DELETE /admin/delete_user/{username}: Belirtilen kullanıcıyı siler (Sadece admin erişebilir).

    POST /admin/admin_check: Mevcut kullanıcının yönetici yetkilerini kontrol eder.


