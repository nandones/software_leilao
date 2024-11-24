package com.mycompany.view;

public class AuctionTimer {
    private int timeRemaining; // Tempo restante em segundos
    private final int initialTime; // Tempo inicial
    private boolean running; // Flag para controle do cronômetro
    private final Runnable onZeroCallback; // Ação ao atingir zero

    public AuctionTimer(int initialTime, Runnable onZeroCallback) {
        this.initialTime = initialTime;
        this.timeRemaining = initialTime;
        this.running = false;
        this.onZeroCallback = onZeroCallback;
    }

    public void start() {
        if (running) return; // Evitar iniciar múltiplas threads
        running = true;
        new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(1000); // Espera 1 segundo
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }

                synchronized (this) {
                    if (timeRemaining > 0) {
                        timeRemaining--;
                        System.out.println("Time remaining: " + timeRemaining + " seconds");
                    }

                    if (timeRemaining == 0) {
                        running = false;
                        onZeroCallback.run(); // Executa a ação ao atingir zero
                    }
                }
            }
        }).start();
    }

    public synchronized void reset() {
        this.timeRemaining = this.initialTime;
        System.out.println("Timer reset to: " + this.initialTime + " seconds");
    }

    public synchronized void stop() {
        this.running = false;
        System.out.println("Timer stopped.");
    }

    public synchronized int getTimeRemaining() {
        return this.timeRemaining;
    }
}
