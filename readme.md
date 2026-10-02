# sysguard

` a simple download folder scanner that scans for viruses and quarantine infected files. `

---
### Long version:
This is a simple download folder scanner (for now) it scans the download folder for virus using `clamav` and `inotify`. When it finds  a virus it notification the user using `notify2`  and `Quarantined` them

### what it uses:
 * `clamav` ==  the main stuff behind the scanner
 * `notify2` == Python interface to DBus notifications
 * `Inotify` == Linux subsystem for filesystem monitoring
 * `pathlib` == Object-oriented filesystem paths
 * `poetry`  == the package manager used here

---
### video:

![](https://www.youtube.com/watch?v=vcAQWKxtBAE)   

---
### how to:

  - install `poetry`

    - install `pipx`
 
    - ``pipx install poetry``

  - set up `poetry`
    
    - `cd` into the folder `sysguard`

    - `poetry install`

    - that all.
  
```
you can use pip or other manager to
but poetry is what i used for this project
so it would be easy for you to
or so what i think at least 
```
 - now run `poetry run python main/main.py`

 ---

### to do list (finished):

- [x] scanning
- [x] file tracking
- [x] Download finish tracking
- [x] Quarantined the file if found to be infected

---

### to do list (not finished):

- [ ] create a config file
- [ ] logging
- [ ] multiple folder scanning
---
### License:
MIT License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

![](https://media1.tenor.com/m/BJ-9w-MUVCMAAAAd/tis100-sad.gif)
