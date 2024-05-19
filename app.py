from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Временное хранилище для записей
entries = []

@app.route('/')
def index():
    return render_template('index.html', entries=entries)

@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        entries.append({'title': title, 'content': content})
        return redirect(url_for('index'))
    return render_template('add_entry.html')

@app.route('/entries')
def view_entries():
    return render_template('view_entries.html', entries=entries)

if __name__ == '__main__':
    app.run(debug=True)
