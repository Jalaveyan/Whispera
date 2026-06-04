export class CustomSelect {
    constructor(selectElement) {
        this.select = selectElement;
        this.select.classList.add('custom-select-hidden');
        this.select.style.display = 'none';

        this.wrapper = document.createElement('div');
        this.wrapper.className = 'custom-select-wrapper';
        this.select.parentNode.insertBefore(this.wrapper, this.select);
        this.wrapper.appendChild(this.select);

        this.customSelect = document.createElement('div');
        this.customSelect.className = 'custom-select';
        this.wrapper.appendChild(this.customSelect);

        this.trigger = document.createElement('div');
        this.trigger.className = 'custom-select-trigger';
        this.trigger.innerHTML = `<span>${this.select.options[this.select.selectedIndex]?.text || ''}</span>`;
        this.customSelect.appendChild(this.trigger);

        this.options = document.createElement('div');
        this.options.className = 'custom-options';
        document.body.appendChild(this.options);

        this.setupOptions();
        this.bindEvents();
    }

    setupOptions() {
        this.options.innerHTML = '';
        for (const option of this.select.options) {
            const customOption = document.createElement('span');
            customOption.className = `custom-option ${option.selected ? 'selected' : ''}`;
            customOption.dataset.value = option.value;
            customOption.textContent = option.text;
            customOption.addEventListener('click', () => {
                this.select.value = option.value;
                this.select.dispatchEvent(new Event('change'));
                this.trigger.querySelector('span').textContent = option.text;
                this.close();
                this.options.querySelectorAll('.custom-option').forEach(opt => opt.classList.remove('selected'));
                customOption.classList.add('selected');
            });
            this.options.appendChild(customOption);
        }
    }

    updatePosition() {
        const rect = this.trigger.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;
        const spaceAbove = rect.top;
        const dropdownHeight = Math.min(this.options.scrollHeight, 300);

        this.options.style.width = `${rect.width}px`;
        this.options.style.left = `${rect.left}px`;

        if (spaceBelow < dropdownHeight && spaceAbove > spaceBelow) {
            this.options.style.top = `${rect.top - dropdownHeight - 8}px`;
            this.options.style.transformOrigin = 'bottom left';
        } else {
            this.options.style.top = `${rect.bottom + 8}px`;
            this.options.style.transformOrigin = 'top left';
        }
    }

    open() {
        document.querySelectorAll('.custom-select').forEach(s => s.classList.remove('open'));
        document.querySelectorAll('.custom-options').forEach(o => {
            if (o !== this.options) {
                o.style.opacity = '0';
                o.style.visibility = 'hidden';
                o.style.pointerEvents = 'none';
            }
        });

        this.customSelect.classList.add('open');
        this.updatePosition();
        this.options.style.opacity = '1';
        this.options.style.visibility = 'visible';
        this.options.style.pointerEvents = 'all';

        this.resizeListener = () => {
            if (this.customSelect.classList.contains('open')) this.updatePosition();
        };
        window.addEventListener('resize', this.resizeListener);
        window.addEventListener('scroll', this.resizeListener, true);
    }

    close() {
        this.customSelect.classList.remove('open');
        this.options.style.opacity = '0';
        this.options.style.visibility = 'hidden';
        this.options.style.pointerEvents = 'none';
        if (this.resizeListener) {
            window.removeEventListener('resize', this.resizeListener);
            window.removeEventListener('scroll', this.resizeListener, true);
        }
    }

    bindEvents() {
        this.trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            if (this.customSelect.classList.contains('open')) {
                this.close();
            } else {
                this.open();
            }
        });

        document.addEventListener('click', (e) => {
            if (!this.wrapper.contains(e.target) && !this.options.contains(e.target)) {
                this.close();
            }
        });
    }
}
