#ifndef MFSC_TWO_SLOT_BUFFER_H
#define MFSC_TWO_SLOT_BUFFER_H

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <sodium/utils.h>
#include <vector>

class TwoSlotBuffer {
public:
  explicit TwoSlotBuffer(size_t slot_capacity)
      : capacity_(slot_capacity),
        slots_{std::vector<unsigned char>(slot_capacity),
               std::vector<unsigned char>(slot_capacity)} {
    free_.push(0);
    free_.push(1);
  }

  ~TwoSlotBuffer() {
    sodium_memzero(slots_[0].data(), capacity_);
    sodium_memzero(slots_[1].data(), capacity_);
  }

  unsigned char *next_writable() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_free_.wait(lock, [this] { return !free_.empty(); });
    producer_slot_ = free_.front();
    free_.pop();
    return slots_[producer_slot_].data();
  }

  void publish(size_t filled_len) {
    std::lock_guard<std::mutex> lock(mutex_);
    len_[producer_slot_] = filled_len;
    ready_.push(producer_slot_);
    cv_ready_.notify_one();
  }

  void finish() {
    std::lock_guard<std::mutex> lock(mutex_);
    done_ = true;
    cv_ready_.notify_all();
  }

  unsigned char *wait_ready(size_t *out_len) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_ready_.wait(lock, [this] { return !ready_.empty() || done_; });
    if (ready_.empty()) {
      return nullptr;
    }
    consumer_slot_ = ready_.front();
    ready_.pop();
    if (out_len) {
      *out_len = len_[consumer_slot_];
    }
    return slots_[consumer_slot_].data();
  }

  void done_with() {
    std::lock_guard<std::mutex> lock(mutex_);
    free_.push(consumer_slot_);
    cv_free_.notify_one();
  }

private:
  size_t capacity_;
  std::vector<unsigned char> slots_[2];
  size_t len_[2] = {0, 0};
  int producer_slot_ = -1;
  int consumer_slot_ = -1;

  std::queue<int> free_;
  std::queue<int> ready_;
  std::mutex mutex_;
  std::condition_variable cv_free_;
  std::condition_variable cv_ready_;
  bool done_ = false;
};

#endif